#!/usr/bin/env bash
set -Eeuo pipefail

# oldxr installer. The 0.9.0 argument selects the current stable
# XrayR v0.9.0 compatibility maintenance release.

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'

REPO="statusX7/oldxr"
MAINTENANCE_0_9_0="v0.9.0-r3"
RELEASE_BASE="${OLDXR_RELEASE_BASE:-https://github.com/${REPO}/releases/download}"
INSTALL_ROOT="${OLDXR_INSTALL_ROOT:-}"
SYSTEMCTL_BIN="${OLDXR_SYSTEMCTL_BIN:-systemctl}"
SKIP_BASE_INSTALL="${OLDXR_SKIP_BASE_INSTALL:-0}"

INSTALL_DIR="${INSTALL_ROOT}/usr/local/XrayR"
CONFIG_DIR="${INSTALL_ROOT}/etc/XrayR"
SERVICE_FILE="${INSTALL_ROOT}/etc/systemd/system/XrayR.service"
MANAGER_FILE="${INSTALL_ROOT}/usr/bin/XrayR"
MANAGER_LINK="${INSTALL_ROOT}/usr/bin/xrayr"

temp_dir=""
active_config_path="/etc/XrayR/config.yml"
active_config_file="${CONFIG_DIR}/config.yml"
active_config_dir="${CONFIG_DIR}"
active_binary_path="/usr/local/XrayR/XrayR"
active_binary_file="${INSTALL_DIR}/XrayR"
existing_version="未识别"
existing_source="未识别"
persistent_backup_dir=""
config_sha_before=""
config_owner_before=""
config_mode_before=""
had_install_dir=0
had_service=0
had_manager=0
had_manager_link=0
had_config=0
service_was_active=0
cleanup() {
    if [[ -n "${temp_dir}" && -d "${temp_dir}" ]]; then
        rm -rf "${temp_dir}"
    fi
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
        echo -e "${red}错误：${plain}未检测到受支持的 Linux 发行版。"
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
        s390x)
            arch_name="s390x"
            ;;
        *)
            echo -e "${red}错误：${plain}当前安装脚本不支持架构 ${machine}。" >&2
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
        yum install -y wget curl unzip tar crontabs socat
    else
        apt-get update
        DEBIAN_FRONTEND=noninteractive apt-get install -y wget curl unzip tar cron socat ca-certificates
    fi
}

run_systemctl() {
    "${SYSTEMCTL_BIN}" "$@"
}

check_status() {
    [[ -f "${SERVICE_FILE}" ]] || return 2
    run_systemctl is-active --quiet XrayR
}

map_install_path() {
    local path="$1"
    if [[ -z "${INSTALL_ROOT}" || "${path}" == "${INSTALL_ROOT}" || "${path}" == "${INSTALL_ROOT}/"* ]]; then
        printf '%s\n' "${path}"
    elif [[ "${path}" == /* ]]; then
        printf '%s%s\n' "${INSTALL_ROOT}" "${path}"
    else
        printf '%s/%s\n' "${INSTALL_ROOT}" "${path}"
    fi
}

trim_service_value() {
    local value="$1"
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
        detected_config="$(trim_service_value "${detected_config}")"
        detected_binary="$(trim_service_value "${detected_binary}")"
    fi

    if [[ -n "${detected_config}" && "${detected_config}" == /* ]]; then
        active_config_path="${detected_config}"
        active_config_file="$(map_install_path "${active_config_path}")"
        active_config_dir="$(dirname "${active_config_file}")"
    fi
    if [[ -n "${detected_binary}" && "${detected_binary}" == /* ]]; then
        active_binary_path="${detected_binary}"
        active_binary_file="$(map_install_path "${active_binary_path}")"
    fi

    if [[ -d "${INSTALL_DIR}" ]]; then had_install_dir=1; fi
    if [[ -f "${SERVICE_FILE}" ]]; then had_service=1; fi
    if [[ -f "${MANAGER_FILE}" ]]; then had_manager=1; fi
    if [[ -e "${MANAGER_LINK}" || -L "${MANAGER_LINK}" ]]; then had_manager_link=1; fi
    if [[ -f "${active_config_file}" ]]; then had_config=1; fi
    if check_status >/dev/null 2>&1; then
        service_was_active=1
    fi

    if [[ -f "${INSTALL_DIR}/.oldxr-release" ]]; then
        existing_source="oldxr"
        existing_version="$(head -n 1 "${INSTALL_DIR}/.oldxr-release")"
    elif [[ -f "${MANAGER_FILE}" ]] && grep -Fq 'statusX7/oldxr' "${MANAGER_FILE}"; then
        existing_source="oldxr"
    elif [[ -f "${MANAGER_FILE}" ]] && grep -Fq 'statusX7/XR' "${MANAGER_FILE}"; then
        existing_source="statusX7/XR legacy"
    elif [[ -f "${MANAGER_FILE}" ]] && grep -Fq 'XrayR-project/XrayR' "${MANAGER_FILE}"; then
        existing_source="official XrayR"
    fi
    if [[ "${existing_version}" == "未识别" && -x "${active_binary_file}" ]]; then
        version_output="$("${active_binary_file}" -version 2>&1 || true)"
        existing_version="$(sed -n '1p' <<<"${version_output}")"
        [[ -n "${existing_version}" ]] || existing_version="未识别"
    fi

    if [[ ${had_install_dir} -eq 1 || ${had_service} -eq 1 || ${had_manager} -eq 1 || ${had_config} -eq 1 ]]; then
        echo "检测到现有安装：来源=${existing_source}，版本=${existing_version}"
        echo "检测到 binary：${active_binary_path}"
        echo "检测到配置：${active_config_path}"
        echo "目标 maintenance release：${resolved_version}"
    else
        echo "未检测到现有安装，将执行全新安装：${resolved_version}"
    fi
}

record_config_metadata() {
    config_sha_before="$(sha256sum "${active_config_file}" | awk '{print $1}')"
    config_owner_before="$(stat -c '%u:%g' "${active_config_file}")"
    config_mode_before="$(stat -c '%a' "${active_config_file}")"
}

backup_existing_install() {
    local timestamp
    local file

    if [[ ${had_install_dir} -eq 0 && ${had_service} -eq 0 && ${had_manager} -eq 0 && ${had_config} -eq 0 ]]; then
        return
    fi

    timestamp="$(date -u +%Y%m%dT%H%M%SZ)-$$"
    persistent_backup_dir="${CONFIG_DIR}/backups/${timestamp}"
    mkdir -p "${persistent_backup_dir}/install" "${persistent_backup_dir}/system" \
        "${persistent_backup_dir}/config/custom" "${persistent_backup_dir}/config/release-data"

    if [[ -f "${active_binary_file}" ]]; then
        cp -a "${active_binary_file}" "${persistent_backup_dir}/install/XrayR"
    fi
    for file in XrayR-fastengine XrayR-legacy XrayR.sh; do
        if [[ -f "${INSTALL_DIR}/${file}" ]]; then
            cp -a "${INSTALL_DIR}/${file}" "${persistent_backup_dir}/install/${file}"
        fi
    done
    if [[ ${had_service} -eq 1 ]]; then
        cp -a "${SERVICE_FILE}" "${persistent_backup_dir}/system/XrayR.service"
    fi
    if [[ ${had_manager} -eq 1 ]]; then
        cp -a "${MANAGER_FILE}" "${persistent_backup_dir}/system/XrayR"
    fi
    if [[ ${had_manager_link} -eq 1 ]]; then
        cp -a "${MANAGER_LINK}" "${persistent_backup_dir}/system/xrayr"
    fi
    if [[ ${had_config} -eq 1 ]]; then
        record_config_metadata
        cp -a "${active_config_file}" "${persistent_backup_dir}/config/config.yml"
    fi
    for file in custom_inbound.json custom_outbound.json route.json dns.json rulelist; do
        if [[ -e "${active_config_dir}/${file}" || -L "${active_config_dir}/${file}" ]]; then
            cp -a "${active_config_dir}/${file}" "${persistent_backup_dir}/config/custom/${file}"
        else
            touch "${persistent_backup_dir}/config/custom/.absent-${file}"
        fi
    done
    for file in geoip.dat geosite.dat; do
        if [[ -e "${active_config_dir}/${file}" || -L "${active_config_dir}/${file}" ]]; then
            cp -a "${active_config_dir}/${file}" "${persistent_backup_dir}/config/release-data/${file}"
        else
            touch "${persistent_backup_dir}/config/release-data/.absent-${file}"
        fi
    done

    {
        printf 'source=%s\n' "${existing_source}"
        printf 'version=%s\n' "${existing_version}"
        printf 'binary_path=%s\n' "${active_binary_path}"
        printf 'config_path=%s\n' "${active_config_path}"
        printf 'config_sha256=%s\n' "${config_sha_before}"
        printf 'config_owner=%s\n' "${config_owner_before}"
        printf 'config_mode=%s\n' "${config_mode_before}"
        printf 'target=%s\n' "${resolved_version}"
        printf 'service_was_active=%s\n' "${service_was_active}"
    } > "${persistent_backup_dir}/manifest"
    chmod 700 "${persistent_backup_dir}"
    echo "升级备份已创建：${persistent_backup_dir}"
}

resolve_version() {
    local requested="${1:-}"
    case "${requested}" in
        ""|0.9.0|v0.9.0)
            resolved_version="${MAINTENANCE_0_9_0}"
            echo "maintenance channel 0.9.0 当前解析为 ${resolved_version}"
            ;;
        0.9.0-r[0-9]*|v0.9.0-r[0-9]*)
            resolved_version="${requested}"
            [[ "${resolved_version}" == v* ]] || resolved_version="v${resolved_version}"
            if [[ ! "${resolved_version}" =~ ^v0\.9\.0-r[0-9]+$ ]]; then
                echo -e "${red}错误：${plain}无效的 maintenance release：${requested}" >&2
                exit 2
            fi
            echo "使用显式 maintenance release：${resolved_version}"
            ;;
        *)
            echo -e "${red}错误：${plain}仅支持 0.9.0 compatibility channel 或显式 0.9.0-rN。" >&2
            exit 2
            ;;
    esac
}

release_requires_fastengine() {
    local revision="${resolved_version##*-r}"
    [[ "${revision}" =~ ^[0-9]+$ ]] && (( revision >= 3 ))
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
    local archive_name="XrayR-linux-${arch_name}.zip"
    local release_url="${RELEASE_BASE}/${resolved_version}"
    local -a required_files
    if release_requires_fastengine && [[ "${arch_name}" != "64" && "${arch_name}" != "arm64-v8a" ]]; then
        echo -e "${red}错误：${plain}${resolved_version} FastEngine Release 仅支持 linux/amd64 与 linux/arm64。" >&2
        exit 2
    fi
    temp_dir="$(mktemp -d)"
    archive_path="${temp_dir}/${archive_name}"
    checksum_path="${archive_path}.sha256"
    stage_dir="${temp_dir}/stage"

    echo "下载 ${REPO} ${resolved_version}：${archive_name}"
    download_file "${release_url}/${archive_name}" "${archive_path}"
    download_file "${release_url}/${archive_name}.sha256" "${checksum_path}"
    (
        cd "${temp_dir}"
        sha256sum --check "${archive_name}.sha256"
    )

    mkdir -p "${stage_dir}"
    unzip -q "${archive_path}" -d "${stage_dir}"
    required_files=(XrayR config.yml geoip.dat geosite.dat XrayR.service XrayR.sh)
    if release_requires_fastengine; then
        required_files+=(XrayR-fastengine XrayR-legacy FASTENGINE-LICENSE FASTENGINE-NOTICE.md)
    fi
    for required in "${required_files[@]}"; do
        if [[ ! -f "${stage_dir}/${required}" ]]; then
            echo -e "${red}错误：${plain}Release archive 缺少 ${required}。" >&2
            exit 1
        fi
    done
    chmod +x "${stage_dir}/XrayR" "${stage_dir}/XrayR.sh"
    if release_requires_fastengine; then
        chmod +x "${stage_dir}/XrayR-fastengine" "${stage_dir}/XrayR-legacy"
    fi
    "${stage_dir}/XrayR" -version
}

install_release() {
    local candidate_dir="${INSTALL_DIR}.new"
    local backup_dir="${INSTALL_DIR}.previous"

    detect_existing_install
    backup_existing_install

    mkdir -p "$(dirname "${INSTALL_DIR}")" "${CONFIG_DIR}" "${active_config_dir}" \
        "$(dirname "${SERVICE_FILE}")" "$(dirname "${MANAGER_FILE}")"
    rm -rf "${candidate_dir}" "${backup_dir}"
    mkdir -p "${candidate_dir}"
    cp -a "${stage_dir}/." "${candidate_dir}/"
    printf '%s\n' "${resolved_version}" > "${candidate_dir}/.oldxr-release"

    run_systemctl stop XrayR >/dev/null 2>&1 || true
    if [[ -d "${INSTALL_DIR}" ]]; then
        if ! mv "${INSTALL_DIR}" "${backup_dir}"; then
            echo -e "${red}错误：${plain}无法暂存现有安装，尚未替换 binary。" >&2
            if [[ ${service_was_active} -eq 1 ]]; then
                run_systemctl start XrayR >/dev/null 2>&1 || true
            fi
            exit 1
        fi
    fi
    if ! mv "${candidate_dir}" "${INSTALL_DIR}"; then
        echo -e "${red}错误：${plain}无法激活候选目录，正在恢复现有安装。" >&2
        rollback_install "${backup_dir}"
        exit 1
    fi

    if ! activate_install; then
        echo -e "${red}错误：${plain}激活 ${resolved_version} 失败，正在回滚现有安装。" >&2
        rollback_install "${backup_dir}"
        exit 1
    fi
    rm -rf "${backup_dir}"

    echo -e "${green}oldxr ${resolved_version} 安装完成。${plain}"
    if [[ -n "${persistent_backup_dir}" ]]; then
        echo "可回滚备份：${persistent_backup_dir}"
    fi
    echo "源码与 Release：https://github.com/${REPO}"
    echo "管理命令：XrayR start|stop|restart|status|log|update|version"
}

activate_install() {
    local file
    local config_sha_after
    local config_owner_after
    local config_mode_after

    cp -f "${INSTALL_DIR}/XrayR.service" "${SERVICE_FILE}" || return 1
    if [[ "${active_config_path}" != "/etc/XrayR/config.yml" ]]; then
        sed -i "s#^ExecStart=.*#ExecStart=/usr/local/XrayR/XrayR --config ${active_config_path}#" "${SERVICE_FILE}" || return 1
    fi
    cp -f "${INSTALL_DIR}/XrayR.sh" "${MANAGER_FILE}" || return 1
    chmod +x "${INSTALL_DIR}/XrayR" "${MANAGER_FILE}" || return 1
    if release_requires_fastengine; then
        chmod +x "${INSTALL_DIR}/XrayR-fastengine" "${INSTALL_DIR}/XrayR-legacy" || return 1
    fi
    rm -f "${MANAGER_LINK}" || return 1
    ln -s "${MANAGER_FILE}" "${MANAGER_LINK}" || return 1

    cp -f "${INSTALL_DIR}/geoip.dat" "${active_config_dir}/geoip.dat" || return 1
    cp -f "${INSTALL_DIR}/geosite.dat" "${active_config_dir}/geosite.dat" || return 1
    if [[ ${had_config} -eq 0 ]]; then
        cp -f "${INSTALL_DIR}/config.yml" "${active_config_file}" || return 1
    fi
    for file in dns.json route.json custom_outbound.json custom_inbound.json rulelist; do
        if [[ ! -e "${active_config_dir}/${file}" && -f "${INSTALL_DIR}/${file}" ]]; then
            cp -f "${INSTALL_DIR}/${file}" "${active_config_dir}/${file}" || return 1
        fi
    done

    if [[ ${had_config} -eq 1 ]]; then
        config_sha_after="$(sha256sum "${active_config_file}" | awk '{print $1}')" || return 1
        config_owner_after="$(stat -c '%u:%g' "${active_config_file}")" || return 1
        config_mode_after="$(stat -c '%a' "${active_config_file}")" || return 1
        if [[ "${config_sha_after}" != "${config_sha_before}" || \
              "${config_owner_after}" != "${config_owner_before}" || \
              "${config_mode_after}" != "${config_mode_before}" ]]; then
            echo -e "${red}错误：${plain}config.yml 的内容、所有者或权限在升级中发生变化。" >&2
            return 1
        fi
        echo "配置已保留：${active_config_path}（SHA256 ${config_sha_after}）"
    fi

    run_systemctl daemon-reload || return 1
    run_systemctl enable XrayR || return 1

    if [[ ${had_config} -eq 1 ]]; then
        run_systemctl start XrayR || return 1
        sleep 2
        check_status || return 1
        echo -e "${green}XrayR service 已启动。${plain}"
    else
        echo -e "${yellow}已写入默认配置；请修改 ${active_config_path} 后执行 XrayR start。${plain}"
    fi
}

restore_file_or_remove() {
    local backup_file="$1"
    local target_file="$2"
    local existed="$3"

    if [[ "${existed}" -eq 1 && ( -e "${backup_file}" || -L "${backup_file}" ) ]]; then
        rm -f "${target_file}"
        cp -a "${backup_file}" "${target_file}"
    elif [[ "${existed}" -eq 0 ]]; then
        rm -f "${target_file}"
    fi
}

rollback_install() {
    local backup_dir="$1"
    local file

    run_systemctl stop XrayR >/dev/null 2>&1 || true
    rm -rf "${INSTALL_DIR}"
    if [[ ${had_install_dir} -eq 1 && -d "${backup_dir}" ]]; then
        mv "${backup_dir}" "${INSTALL_DIR}"
    fi

    if [[ -n "${persistent_backup_dir}" ]]; then
        restore_file_or_remove "${persistent_backup_dir}/system/XrayR.service" "${SERVICE_FILE}" "${had_service}"
        restore_file_or_remove "${persistent_backup_dir}/system/XrayR" "${MANAGER_FILE}" "${had_manager}"
        restore_file_or_remove "${persistent_backup_dir}/system/xrayr" "${MANAGER_LINK}" "${had_manager_link}"
        if [[ ${had_config} -eq 1 && -f "${persistent_backup_dir}/config/config.yml" ]]; then
            cp -a "${persistent_backup_dir}/config/config.yml" "${active_config_file}"
        fi
        for file in custom_inbound.json custom_outbound.json route.json dns.json rulelist; do
            if [[ -e "${persistent_backup_dir}/config/custom/${file}" || -L "${persistent_backup_dir}/config/custom/${file}" ]]; then
                rm -f "${active_config_dir}/${file}"
                cp -a "${persistent_backup_dir}/config/custom/${file}" "${active_config_dir}/${file}"
            elif [[ -f "${persistent_backup_dir}/config/custom/.absent-${file}" ]]; then
                rm -f "${active_config_dir}/${file}"
            fi
        done
        for file in geoip.dat geosite.dat; do
            if [[ -e "${persistent_backup_dir}/config/release-data/${file}" || -L "${persistent_backup_dir}/config/release-data/${file}" ]]; then
                rm -f "${active_config_dir}/${file}"
                cp -a "${persistent_backup_dir}/config/release-data/${file}" "${active_config_dir}/${file}"
            elif [[ -f "${persistent_backup_dir}/config/release-data/.absent-${file}" ]]; then
                rm -f "${active_config_dir}/${file}"
            fi
        done
    else
        rm -f "${SERVICE_FILE}" "${MANAGER_FILE}" "${MANAGER_LINK}"
        if [[ ${had_config} -eq 0 ]]; then
            rm -f "${active_config_file}"
        fi
        rm -f "${active_config_dir}/geoip.dat" "${active_config_dir}/geosite.dat"
        for file in custom_inbound.json custom_outbound.json route.json dns.json rulelist; do
            rm -f "${active_config_dir}/${file}"
        done
    fi

    run_systemctl daemon-reload >/dev/null 2>&1 || true
    if [[ ${service_was_active} -eq 1 ]]; then
        run_systemctl start XrayR >/dev/null 2>&1 || true
    fi
    echo -e "${yellow}已恢复升级前的 binary、service、管理脚本与用户配置。${plain}" >&2
    if [[ -n "${persistent_backup_dir}" ]]; then
        echo "回滚备份保留在：${persistent_backup_dir}" >&2
    fi
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
