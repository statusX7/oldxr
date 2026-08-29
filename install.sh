#!/usr/bin/env bash
set -Eeuo pipefail

# oldxr v1.0.x single-binary installer.

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'

REPO="statusX7/oldxr"
CURRENT_V1="v1.0.2"
RELEASE_BASE="${OLDXR_RELEASE_BASE:-https://github.com/${REPO}/releases/download}"
DEFAULT_CONFIG_COMMIT="be6995621ea95229e2674bd5575f21852d96e00a"
DEFAULT_CONFIG_SHA256="52c98378453b227412f8d59df4d144cf750172a629a5ea6d98c940ece3633849"
DEFAULT_CONFIG_URL="${OLDXR_DEFAULT_CONFIG_URL:-https://raw.githubusercontent.com/${REPO}/${DEFAULT_CONFIG_COMMIT}/main/config.yml.example}"
INSTALL_ROOT="${OLDXR_INSTALL_ROOT:-}"
SYSTEMCTL_BIN="${OLDXR_SYSTEMCTL_BIN:-systemctl}"
SKIP_BASE_INSTALL="${OLDXR_SKIP_BASE_INSTALL:-0}"
HEALTH_WAIT_SECONDS="${OLDXR_HEALTH_WAIT_SECONDS:-2}"

INSTALL_DIR="${INSTALL_ROOT}/usr/local/XrayR"
CONFIG_DIR="${INSTALL_ROOT}/etc/XrayR"
BACKUP_ROOT="${CONFIG_DIR}/backups"
SERVICE_FILE="${INSTALL_ROOT}/etc/systemd/system/XrayR.service"
MANAGER_FILE="${INSTALL_ROOT}/usr/bin/XrayR"
MANAGER_LINK="${INSTALL_ROOT}/usr/bin/xrayr"

temp_dir=""
stage_dir=""
candidate_dir=""
immediate_backup_dir=""
persistent_backup_dir=""
resolved_version=""
archive_name=""
active_config_path="/etc/XrayR/config.yml"
active_config_file="${CONFIG_DIR}/config.yml"
active_config_dir="${CONFIG_DIR}"
active_config_logical_dir="/etc/XrayR"
active_binary_path="/usr/local/XrayR/XrayR"
active_binary_file="${INSTALL_DIR}/XrayR"
existing_version="未识别"
existing_source="未识别"
had_install_dir=0
had_service=0
had_manager=0
had_manager_link=0
had_config=0
had_runtime=0
service_was_active=0
transaction_started=0
transaction_committed=0
rollback_done=0

declare -a user_paths=()
declare -a user_files=()
declare -a user_existed=()
declare -a user_kind=()
declare -a user_digest=()
declare -a user_owner=()
declare -a user_mode=()

run_systemctl() {
    "${SYSTEMCTL_BIN}" "$@"
}

check_status() {
    [[ -f "${SERVICE_FILE}" ]] || return 2
    run_systemctl is-active --quiet XrayR
}

remove_fixed_tree() {
    local target="$1"
    case "${target}" in
        "${INSTALL_DIR}.new."*|"${INSTALL_DIR}.previous."*|"${temp_dir}")
            [[ -n "${target}" && "${target}" != "/" ]] && rm -rf -- "${target}"
            ;;
        *)
            echo -e "${red}错误：${plain}拒绝清理非固定临时目录：${target}" >&2
            return 1
            ;;
    esac
}

cleanup() {
    local status=$?
    if [[ ${transaction_started} -eq 1 && ${transaction_committed} -eq 0 && ${rollback_done} -eq 0 ]]; then
        rollback_install || true
    fi
    if [[ -n "${candidate_dir}" && -d "${candidate_dir}" ]]; then
        remove_fixed_tree "${candidate_dir}" || true
    fi
    if [[ -n "${temp_dir}" && -d "${temp_dir}" ]]; then
        remove_fixed_tree "${temp_dir}" || true
    fi
    return "${status}"
}
trap cleanup EXIT

[[ ${EUID} -ne 0 ]] && echo -e "${red}错误：${plain}必须使用 root 用户运行此脚本！" && exit 1

detect_os() {
    if [[ -f /etc/redhat-release ]]; then
        release="centos"
    elif grep -Eqi "debian" /etc/issue 2>/dev/null || grep -Eqi "debian" /proc/version 2>/dev/null; then
        release="debian"
    elif grep -Eqi "ubuntu" /etc/issue 2>/dev/null || grep -Eqi "ubuntu" /proc/version 2>/dev/null; then
        release="ubuntu"
    elif grep -Eqi "centos|red hat|redhat" /etc/issue 2>/dev/null || grep -Eqi "centos|red hat|redhat" /proc/version 2>/dev/null; then
        release="centos"
    else
        echo -e "${red}错误：${plain}未检测到受支持的 Linux 发行版。" >&2
        exit 1
    fi
}

detect_arch() {
    local machine
    machine="${OLDXR_ARCH:-$(uname -m)}"
    case "${machine}" in
        x86_64|x64|amd64)
            arch_name="64"
            ;;
        aarch64|arm64)
            arch_name="arm64-v8a"
            ;;
        *)
            echo -e "${red}错误：${plain}oldxr v1.0.x Release 仅支持 linux/amd64 与 linux/arm64；当前为 ${machine}。" >&2
            exit 2
            ;;
    esac
    echo "检测到架构：${machine}（asset: linux-${arch_name}）"
}

install_base() {
    if [[ "${SKIP_BASE_INSTALL}" == "1" ]]; then
        echo -e "${yellow}测试模式：跳过系统依赖安装。${plain}"
        return
    fi
    if [[ "${release}" == "centos" ]]; then
        yum install -y curl unzip ca-certificates
    else
        apt-get update
        DEBIAN_FRONTEND=noninteractive apt-get install -y curl unzip ca-certificates
    fi
}

map_install_path() {
    local logical_path="$1"
    if [[ -z "${INSTALL_ROOT}" || "${logical_path}" == "${INSTALL_ROOT}" || "${logical_path}" == "${INSTALL_ROOT}/"* ]]; then
        printf '%s\n' "${logical_path}"
    elif [[ "${logical_path}" == /* ]]; then
        printf '%s%s\n' "${INSTALL_ROOT}" "${logical_path}"
    else
        printf '%s/%s\n' "${INSTALL_ROOT}" "${logical_path}"
    fi
}

trim_value() {
    local value="$1"
    value="$(sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//; s/[[:space:]]+#.*$//' <<<"${value}")"
    value="${value#\"}"
    value="${value%\"}"
    value="${value#\'}"
    value="${value%\'}"
    printf '%s\n' "${value}"
}

detect_existing_install() {
    local exec_start=""
    local detected_config=""
    local detected_binary=""
    local version_output=""

    if [[ -f "${SERVICE_FILE}" ]]; then
        exec_start="$(sed -n 's/^[[:space:]]*ExecStart=//p' "${SERVICE_FILE}" | head -n 1)"
        detected_config="$(sed -n \
            -e 's/.*--config[=[:space:]]\([^[:space:]]*\).*/\1/p' \
            -e 's/.*-config[=[:space:]]\([^[:space:]]*\).*/\1/p' \
            <<<"${exec_start}" | head -n 1)"
        detected_binary="${exec_start%%[[:space:]]*}"
        detected_config="$(trim_value "${detected_config}")"
        detected_binary="$(trim_value "${detected_binary}")"
    fi

    if [[ -n "${detected_config}" && "${detected_config}" == /* ]]; then
        active_config_path="${detected_config}"
        active_config_file="$(map_install_path "${active_config_path}")"
        active_config_dir="$(dirname "${active_config_file}")"
        active_config_logical_dir="$(dirname "${active_config_path}")"
    fi
    if [[ -n "${detected_binary}" && "${detected_binary}" == /* ]]; then
        active_binary_path="${detected_binary}"
        active_binary_file="$(map_install_path "${active_binary_path}")"
    fi

    [[ -d "${INSTALL_DIR}" ]] && had_install_dir=1
    [[ -f "${SERVICE_FILE}" ]] && had_service=1
    [[ -f "${MANAGER_FILE}" ]] && had_manager=1
    [[ -e "${MANAGER_LINK}" || -L "${MANAGER_LINK}" ]] && had_manager_link=1
    [[ -f "${active_config_file}" ]] && had_config=1
    if [[ -x "${active_binary_file}" || ${had_service} -eq 1 || ${had_manager} -eq 1 ]]; then
        had_runtime=1
    fi
    if check_status >/dev/null 2>&1; then
        service_was_active=1
    fi

    if [[ -f "${INSTALL_DIR}/.oldxr-release" ]]; then
        existing_source="oldxr"
        existing_version="$(head -n 1 "${INSTALL_DIR}/.oldxr-release")"
    elif [[ -f "${MANAGER_FILE}" ]] && grep -Fq 'statusX7/oldxr' "${MANAGER_FILE}"; then
        existing_source="oldxr"
    elif [[ -f "${MANAGER_FILE}" ]] && grep -Fq 'XrayR-project/XrayR' "${MANAGER_FILE}"; then
        existing_source="official XrayR"
    fi
    if [[ -x "${active_binary_file}" ]]; then
        version_output="$("${active_binary_file}" -version 2>&1 || true)"
        if [[ "${existing_version}" == "未识别" ]]; then
            existing_version="$(sed -n '1p' <<<"${version_output}")"
            [[ -n "${existing_version}" ]] || existing_version="未识别"
        fi
        if [[ "${existing_source}" == "未识别" && "${version_output}" == XrayR\ 0.9.0* ]]; then
            existing_source="official-compatible XrayR v0.9.0"
        fi
    fi

    if [[ ${had_runtime} -eq 1 ]]; then
        case "${existing_source}:${existing_version}" in
            "official XrayR:"*|"official-compatible XrayR v0.9.0:"*|"oldxr:v1."*|"oldxr:XrayR 1."*)
                ;;
            *)
                if [[ "${OLDXR_ALLOW_UNRECOGNIZED_UPGRADE:-0}" != "1" ]]; then
                    echo -e "${red}错误：${plain}现有安装不是可确认的官方 XrayR v0.9.0 或 oldxr v1.x；为避免破坏未知安装，已停止。" >&2
                    echo "检测结果：来源=${existing_source}，版本=${existing_version}" >&2
                    exit 1
                fi
                echo -e "${yellow}警告：测试覆盖已允许升级无法识别的现有安装。${plain}"
                ;;
        esac
    fi

    if [[ ${had_runtime} -eq 1 || ${had_config} -eq 1 || ${had_install_dir} -eq 1 ]]; then
        echo "检测到现有安装：来源=${existing_source}，版本=${existing_version}"
        echo "检测到 binary：${active_binary_path}"
        echo "检测到配置：${active_config_path}"
        echo "目标版本：${resolved_version}"
    else
        echo "未检测到现有安装，将执行全新安装：${resolved_version}"
    fi
}

resolve_user_path() {
    local value="$1"
    value="$(trim_value "${value}")"
    [[ -n "${value}" ]] || return 1
    case "${value}" in
        /*)
            printf '%s\n' "${value}"
            ;;
        *'$'*|*'{'*|*'}'*)
            return 1
            ;;
        *)
            printf '%s/%s\n' "${active_config_logical_dir}" "${value}"
            ;;
    esac
}

register_user_path() {
    local logical_path="$1"
    local mapped_path
    local index
    local kind="absent"
    local digest="-"
    local owner="-"
    local mode="-"
    local existed=0

    [[ "${logical_path}" == /* && "${logical_path}" != "/" ]] || return 0
    for index in "${!user_paths[@]}"; do
        [[ "${user_paths[index]}" == "${logical_path}" ]] && return 0
    done
    mapped_path="$(map_install_path "${logical_path}")"
    if [[ -L "${mapped_path}" ]]; then
        kind="symlink"
        digest="$(readlink "${mapped_path}")"
        owner="$(stat -c '%u:%g' "${mapped_path}")"
        mode="$(stat -c '%a' "${mapped_path}")"
        existed=1
    elif [[ -f "${mapped_path}" ]]; then
        kind="file"
        digest="$(sha256sum "${mapped_path}" | awk '{print $1}')"
        owner="$(stat -c '%u:%g' "${mapped_path}")"
        mode="$(stat -c '%a' "${mapped_path}")"
        existed=1
    fi
    user_paths+=("${logical_path}")
    user_files+=("${mapped_path}")
    user_existed+=("${existed}")
    user_kind+=("${kind}")
    user_digest+=("${digest}")
    user_owner+=("${owner}")
    user_mode+=("${mode}")
}

collect_user_paths() {
    local file
    local raw_value
    local resolved_path
    register_user_path "${active_config_path}"
    for file in dns.json route.json custom_outbound.json custom_inbound.json rulelist geoip.dat geosite.dat; do
        register_user_path "${active_config_logical_dir}/${file}"
    done
    if [[ -f "${active_config_file}" ]]; then
        while IFS= read -r raw_value; do
            if resolved_path="$(resolve_user_path "${raw_value}")"; then
                register_user_path "${resolved_path}"
            fi
        done < <(sed -nE 's/^[[:space:]]*(DnsConfigPath|RouteConfigPath|InboundConfigPath|OutboundConfigPath|RuleListPath|CertFile|KeyFile):[[:space:]]*(.*)$/\2/p' "${active_config_file}")
    fi
}

path_digest_matches() {
    local index="$1"
    local mapped="${user_files[index]}"
    case "${user_kind[index]}" in
        file)
            [[ -f "${mapped}" ]] && [[ "$(sha256sum "${mapped}" | awk '{print $1}')" == "${user_digest[index]}" ]]
            ;;
        symlink)
            [[ -L "${mapped}" ]] && [[ "$(readlink "${mapped}")" == "${user_digest[index]}" ]]
            ;;
        *)
            return 1
            ;;
    esac
}

verify_user_paths() {
    local index
    for index in "${!user_paths[@]}"; do
        [[ "${user_existed[index]}" -eq 1 ]] || continue
        if ! path_digest_matches "${index}" || \
            [[ "$(stat -c '%u:%g' "${user_files[index]}")" != "${user_owner[index]}" ]] || \
            [[ "$(stat -c '%a' "${user_files[index]}")" != "${user_mode[index]}" ]]; then
            echo -e "${red}错误：${plain}升级改变了用户文件：${user_paths[index]}" >&2
            return 1
        fi
    done
    return 0
}

backup_existing_install() {
    local timestamp
    local index
    local backup_file

    if [[ ${had_install_dir} -eq 0 && ${had_service} -eq 0 && ${had_manager} -eq 0 && ${had_config} -eq 0 ]]; then
        return
    fi
    timestamp="$(date -u +%Y%m%dT%H%M%SZ)-$$"
    persistent_backup_dir="${BACKUP_ROOT}/${timestamp}"
    mkdir -p "${persistent_backup_dir}/files" "${persistent_backup_dir}/system"
    chmod 700 "${persistent_backup_dir}"

    if [[ -d "${INSTALL_DIR}" ]]; then
        cp -a "${INSTALL_DIR}" "${persistent_backup_dir}/install-dir"
    fi
    [[ ${had_service} -eq 1 ]] && cp -a "${SERVICE_FILE}" "${persistent_backup_dir}/system/XrayR.service"
    [[ ${had_manager} -eq 1 ]] && cp -a "${MANAGER_FILE}" "${persistent_backup_dir}/system/XrayR"
    [[ ${had_manager_link} -eq 1 ]] && cp -a "${MANAGER_LINK}" "${persistent_backup_dir}/system/xrayr"

    : > "${persistent_backup_dir}/manifest"
    {
        printf 'source=%s\n' "${existing_source}"
        printf 'version=%s\n' "${existing_version}"
        printf 'binary_path=%s\n' "${active_binary_path}"
        printf 'config_path=%s\n' "${active_config_path}"
        printf 'target=%s\n' "${resolved_version}"
        printf 'service_was_active=%s\n' "${service_was_active}"
    } >> "${persistent_backup_dir}/manifest"
    for index in "${!user_paths[@]}"; do
        printf 'user_path\t%s\t%s\t%s\t%s\t%s\n' \
            "${user_paths[index]}" "${user_kind[index]}" "${user_digest[index]}" \
            "${user_owner[index]}" "${user_mode[index]}" >> "${persistent_backup_dir}/manifest"
        [[ "${user_existed[index]}" -eq 1 ]] || continue
        backup_file="${persistent_backup_dir}/files${user_paths[index]}"
        mkdir -p "$(dirname "${backup_file}")"
        cp -a "${user_files[index]}" "${backup_file}"
    done
    echo "升级备份已创建：${persistent_backup_dir}"
}

resolve_version() {
    local requested="${1:-}"
    case "${requested}" in
        ""|1.0.2|v1.0.2)
            resolved_version="${CURRENT_V1}"
            ;;
        1.0.[0-9]*|v1.0.[0-9]*)
            resolved_version="${requested}"
            [[ "${resolved_version}" == v* ]] || resolved_version="v${resolved_version}"
            [[ "${resolved_version}" =~ ^v1\.0\.[0-9]+$ ]] || {
                echo -e "${red}错误：${plain}无效的 oldxr v1.0.x 版本：${requested}" >&2
                exit 2
            }
            ;;
        *)
            echo -e "${red}错误：${plain}此安装器仅支持 oldxr v1.0.x；正式版本为 1.0.2。" >&2
            exit 2
            ;;
    esac
    echo "目标 oldxr 版本：${resolved_version}"
}

download_file() {
    local url="$1"
    local output="$2"
    if ! curl --fail --location --silent --show-error --retry 3 --output "${output}" "${url}"; then
        echo -e "${red}下载失败：${url}${plain}" >&2
        exit 1
    fi
}

download_and_verify_release() {
    local release_url="${RELEASE_BASE}/${resolved_version}"
    local expected_sha
    local actual_sha
    local entry
    local version_line
    local -a required_files=(
        XrayR XrayR.service XrayR.sh config.yml geoip.dat geosite.dat
        dns.json route.json custom_outbound.json custom_inbound.json rulelist
    )

    archive_name="XrayR-linux-${arch_name}.zip"
    temp_dir="$(mktemp -d)"
    archive_path="${temp_dir}/${archive_name}"
    checksum_path="${archive_path}.sha256"
    stage_dir="${temp_dir}/stage"

    echo "下载 ${REPO} ${resolved_version}：${archive_name}"
    download_file "${release_url}/${archive_name}" "${archive_path}"
    download_file "${release_url}/${archive_name}.sha256" "${checksum_path}"
    expected_sha="$(awk 'NF {print $1; exit}' "${checksum_path}")"
    [[ "${expected_sha}" =~ ^[0-9a-fA-F]{64}$ ]] || {
        echo -e "${red}错误：${plain}Release checksum 格式无效。" >&2
        exit 1
    }
    actual_sha="$(sha256sum "${archive_path}" | awk '{print $1}')"
    [[ "${actual_sha,,}" == "${expected_sha,,}" ]] || {
        echo -e "${red}错误：${plain}Release checksum 不匹配，服务尚未停止。" >&2
        exit 1
    }

    while IFS= read -r entry; do
        case "${entry}" in
            /*|../*|*/../*|*'/..')
                echo -e "${red}错误：${plain}Release archive 包含不安全路径：${entry}" >&2
                exit 1
                ;;
        esac
    done < <(unzip -Z1 "${archive_path}")
    mkdir -p "${stage_dir}"
    unzip -q "${archive_path}" -d "${stage_dir}"
    for entry in "${required_files[@]}"; do
        [[ -f "${stage_dir}/${entry}" ]] || {
            echo -e "${red}错误：${plain}Release archive 缺少 ${entry}。" >&2
            exit 1
        }
    done
    if [[ -e "${stage_dir}/XrayR-fastengine" || -e "${stage_dir}/XrayR-legacy" ]]; then
        echo -e "${red}错误：${plain}v1.0.x archive 不得包含旧多二进制 sidecar。" >&2
        exit 1
    fi
    chmod +x "${stage_dir}/XrayR" "${stage_dir}/XrayR.sh"
    version_line="$("${stage_dir}/XrayR" -version 2>&1 | sed -n '1p')"
    [[ "${version_line}" == "XrayR ${resolved_version#v} "* || "${version_line}" == "XrayR ${resolved_version#v}"* ]] || {
        echo -e "${red}错误：${plain}候选 binary 版本不匹配：${version_line}" >&2
        exit 1
    }
    echo "Release SHA256：${actual_sha}"
}

stage_fresh_default_config() {
    local downloaded_config
    local actual_sha

    if [[ ${had_runtime} -ne 0 || ${had_config} -ne 0 || ${had_install_dir} -ne 0 ]]; then
        echo "检测到现有安装或配置，保留用户 config.yml。"
        return
    fi

    downloaded_config="${temp_dir}/default-config.yml"
    echo "下载经过校验的新装默认配置：${DEFAULT_CONFIG_COMMIT}"
    download_file "${DEFAULT_CONFIG_URL}" "${downloaded_config}"
    actual_sha="$(sha256sum "${downloaded_config}" | awk '{print $1}')"
    [[ "${actual_sha}" == "${DEFAULT_CONFIG_SHA256}" ]] || {
        echo -e "${red}错误：${plain}新装默认配置 SHA256 不匹配，服务尚未停止。" >&2
        exit 1
    }
    cp -f -- "${downloaded_config}" "${stage_dir}/config.yml"
    echo "新装默认配置 SHA256：${actual_sha}"
}

prepare_candidate() {
    candidate_dir="${INSTALL_DIR}.new.$$"
    immediate_backup_dir="${INSTALL_DIR}.previous.$$"
    remove_fixed_tree "${candidate_dir}" 2>/dev/null || true
    remove_fixed_tree "${immediate_backup_dir}" 2>/dev/null || true
    mkdir -p "${candidate_dir}"
    cp -a "${stage_dir}/." "${candidate_dir}/"
    chmod +x "${candidate_dir}/XrayR" "${candidate_dir}/XrayR.sh"
    printf '%s\n' "${resolved_version}" > "${candidate_dir}/.oldxr-release"
}

install_missing_user_file() {
    local source_name="$1"
    local target_path="$2"
    [[ -e "${target_path}" || -L "${target_path}" ]] && return 0
    mkdir -p "$(dirname "${target_path}")"
    cp -a "${INSTALL_DIR}/${source_name}" "${target_path}"
}

activate_install() {
    local file

    mkdir -p "$(dirname "${SERVICE_FILE}")" "$(dirname "${MANAGER_FILE}")" "${active_config_dir}"
    cp -f "${INSTALL_DIR}/XrayR.service" "${SERVICE_FILE}" || return 1
    sed -i "s#^ExecStart=.*#ExecStart=/usr/local/XrayR/XrayR --config ${active_config_path}#" "${SERVICE_FILE}" || return 1
    cp -f "${INSTALL_DIR}/XrayR.sh" "${MANAGER_FILE}" || return 1
    chmod +x "${INSTALL_DIR}/XrayR" "${INSTALL_DIR}/XrayR.sh" "${MANAGER_FILE}" || return 1
    rm -f -- "${MANAGER_LINK}" || return 1
    ln -s /usr/bin/XrayR "${MANAGER_LINK}" || return 1

    install_missing_user_file config.yml "${active_config_file}" || return 1
    for file in dns.json route.json custom_outbound.json custom_inbound.json rulelist geoip.dat geosite.dat; do
        install_missing_user_file "${file}" "${active_config_dir}/${file}" || return 1
    done
    verify_user_paths || return 1

    run_systemctl daemon-reload || return 1
    run_systemctl enable XrayR || return 1
    if [[ ${had_config} -eq 1 ]]; then
        run_systemctl start XrayR || return 1
        if [[ "${HEALTH_WAIT_SECONDS}" != "0" ]]; then
            sleep "${HEALTH_WAIT_SECONDS}"
        fi
        check_status || return 1
        echo -e "${green}XrayR service 已启动。${plain}"
    else
        echo -e "${yellow}已写入默认配置；请修改 ${active_config_path} 后执行 XrayR start。${plain}"
    fi
}

restore_runtime_file() {
    local backup_file="$1"
    local target_file="$2"
    local existed="$3"
    rm -f -- "${target_file}"
    if [[ "${existed}" -eq 1 && ( -e "${backup_file}" || -L "${backup_file}" ) ]]; then
        mkdir -p "$(dirname "${target_file}")"
        cp -a "${backup_file}" "${target_file}"
    fi
}

rollback_install() {
    local index
    local backup_file
    [[ ${rollback_done} -eq 0 ]] || return 0
    rollback_done=1

    run_systemctl stop XrayR >/dev/null 2>&1 || true
    if [[ -d "${INSTALL_DIR}" ]]; then
        rm -rf -- "${INSTALL_DIR}"
    fi
    if [[ ${had_install_dir} -eq 1 && -n "${immediate_backup_dir}" && -d "${immediate_backup_dir}" ]]; then
        mv "${immediate_backup_dir}" "${INSTALL_DIR}" || true
    fi

    if [[ -n "${persistent_backup_dir}" ]]; then
        restore_runtime_file "${persistent_backup_dir}/system/XrayR.service" "${SERVICE_FILE}" "${had_service}"
        restore_runtime_file "${persistent_backup_dir}/system/XrayR" "${MANAGER_FILE}" "${had_manager}"
        restore_runtime_file "${persistent_backup_dir}/system/xrayr" "${MANAGER_LINK}" "${had_manager_link}"
        for index in "${!user_paths[@]}"; do
            if [[ "${user_existed[index]}" -eq 1 ]]; then
                backup_file="${persistent_backup_dir}/files${user_paths[index]}"
                rm -f -- "${user_files[index]}"
                mkdir -p "$(dirname "${user_files[index]}")"
                cp -a "${backup_file}" "${user_files[index]}" || true
            else
                rm -f -- "${user_files[index]}" || true
            fi
        done
    else
        restore_runtime_file /nonexistent "${SERVICE_FILE}" "${had_service}"
        restore_runtime_file /nonexistent "${MANAGER_FILE}" "${had_manager}"
        restore_runtime_file /nonexistent "${MANAGER_LINK}" "${had_manager_link}"
        for index in "${!user_paths[@]}"; do
            if [[ "${user_existed[index]}" -eq 0 ]]; then
                rm -f -- "${user_files[index]}" || true
            fi
        done
    fi

    run_systemctl daemon-reload >/dev/null 2>&1 || true
    if [[ ${service_was_active} -eq 1 ]]; then
        run_systemctl start XrayR >/dev/null 2>&1 || true
    fi
    echo -e "${yellow}已恢复升级前的 binary、service、管理脚本与用户文件。${plain}" >&2
    [[ -n "${persistent_backup_dir}" ]] && echo "回滚备份保留在：${persistent_backup_dir}" >&2
}

install_release() {
    detect_existing_install
    stage_fresh_default_config
    collect_user_paths
    backup_existing_install
    prepare_candidate

    mkdir -p "$(dirname "${INSTALL_DIR}")"
    transaction_started=1
    run_systemctl stop XrayR >/dev/null 2>&1 || true
    if [[ -d "${INSTALL_DIR}" ]]; then
        mv "${INSTALL_DIR}" "${immediate_backup_dir}"
    fi
    mv "${candidate_dir}" "${INSTALL_DIR}"
    candidate_dir=""
    activate_install
    transaction_committed=1
    if [[ -n "${immediate_backup_dir}" && -d "${immediate_backup_dir}" ]]; then
        remove_fixed_tree "${immediate_backup_dir}"
    fi

    echo -e "${green}oldxr ${resolved_version} 安装完成。${plain}"
    [[ -n "${persistent_backup_dir}" ]] && echo "可回滚备份：${persistent_backup_dir}"
    echo "源码与 Release：https://github.com/${REPO}"
    echo "管理命令：XrayR start|stop|restart|status|log|update|version"
}

main() {
    detect_os
    detect_arch
    resolve_version "${1:-}"
    install_base
    download_and_verify_release
    install_release
}

main "$@"
