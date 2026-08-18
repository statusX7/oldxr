#!/usr/bin/env bash
set -Eeuo pipefail

# oldxr installer. The 0.9.0 argument selects the current stable
# XrayR v0.9.0 compatibility maintenance release.

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'

REPO="statusX7/oldxr"
MAINTENANCE_0_9_0="v0.9.0-r1"
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
    for required in XrayR config.yml geoip.dat geosite.dat XrayR.service XrayR.sh; do
        if [[ ! -f "${stage_dir}/${required}" ]]; then
            echo -e "${red}错误：${plain}Release archive 缺少 ${required}。" >&2
            exit 1
        fi
    done
    chmod +x "${stage_dir}/XrayR" "${stage_dir}/XrayR.sh"
    "${stage_dir}/XrayR" -version
}

install_release() {
    local had_config=0
    local candidate_dir="${INSTALL_DIR}.new"
    local backup_dir="${INSTALL_DIR}.previous"
    [[ -f "${CONFIG_DIR}/config.yml" ]] && had_config=1

    mkdir -p "$(dirname "${INSTALL_DIR}")" "${CONFIG_DIR}" "$(dirname "${SERVICE_FILE}")" "$(dirname "${MANAGER_FILE}")"
    rm -rf "${candidate_dir}" "${backup_dir}"
    mkdir -p "${candidate_dir}"
    cp -a "${stage_dir}/." "${candidate_dir}/"

    run_systemctl stop XrayR >/dev/null 2>&1 || true
    if [[ -d "${INSTALL_DIR}" ]]; then
        mv "${INSTALL_DIR}" "${backup_dir}"
    fi
    mv "${candidate_dir}" "${INSTALL_DIR}"

    if ! activate_install "${had_config}"; then
        echo -e "${red}错误：${plain}激活 ${resolved_version} 失败，正在恢复先前 binary。" >&2
        rm -rf "${INSTALL_DIR}"
        if [[ -d "${backup_dir}" ]]; then
            mv "${backup_dir}" "${INSTALL_DIR}"
            run_systemctl daemon-reload >/dev/null 2>&1 || true
            run_systemctl start XrayR >/dev/null 2>&1 || true
        fi
        exit 1
    fi
    rm -rf "${backup_dir}"

    echo -e "${green}oldxr ${resolved_version} 安装完成。${plain}"
    echo "源码与 Release：https://github.com/${REPO}"
    echo "管理命令：XrayR start|stop|restart|status|log|update|version"
}

activate_install() {
    local had_config="$1"
    local file

    cp -f "${INSTALL_DIR}/XrayR.service" "${SERVICE_FILE}" || return 1
    cp -f "${INSTALL_DIR}/XrayR.sh" "${MANAGER_FILE}" || return 1
    chmod +x "${INSTALL_DIR}/XrayR" "${MANAGER_FILE}" || return 1
    rm -f "${MANAGER_LINK}" || return 1
    ln -s "${MANAGER_FILE}" "${MANAGER_LINK}" || return 1

    cp -f "${INSTALL_DIR}/geoip.dat" "${CONFIG_DIR}/geoip.dat" || return 1
    cp -f "${INSTALL_DIR}/geosite.dat" "${CONFIG_DIR}/geosite.dat" || return 1
    if [[ ${had_config} -eq 0 ]]; then
        cp -f "${INSTALL_DIR}/config.yml" "${CONFIG_DIR}/config.yml" || return 1
    fi
    for file in dns.json route.json custom_outbound.json custom_inbound.json rulelist; do
        if [[ ! -f "${CONFIG_DIR}/${file}" && -f "${INSTALL_DIR}/${file}" ]]; then
            cp -f "${INSTALL_DIR}/${file}" "${CONFIG_DIR}/${file}" || return 1
        fi
    done

    run_systemctl daemon-reload || return 1
    run_systemctl enable XrayR || return 1

    if [[ ${had_config} -eq 1 ]]; then
        run_systemctl start XrayR || return 1
        sleep 2
        check_status || return 1
        echo -e "${green}XrayR service 已启动。${plain}"
    else
        echo -e "${yellow}已写入默认配置；请修改 ${CONFIG_DIR}/config.yml 后执行 XrayR start。${plain}"
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
