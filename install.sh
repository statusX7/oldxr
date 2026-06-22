#!/usr/bin/env bash
set -Eeuo pipefail

# XrayR installer for statusX7/XR
# Based on the original XrayR-release install flow, with download sources changed to:
#   https://github.com/statusX7/XR
#
# Usage:
#   bash <(curl -Ls https://raw.githubusercontent.com/statusX7/XR/master/install.sh) 0.9.0
#   bash <(curl -Ls https://raw.githubusercontent.com/statusX7/XR/master/install.sh) v0.9.0
#   bash <(curl -Ls https://raw.githubusercontent.com/statusX7/XR/master/install.sh)

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'

REPO="statusX7/XR"
BRANCH="master"
RAW_BASE="https://raw.githubusercontent.com/${REPO}/${BRANCH}"
GITHUB_RELEASES="https://github.com/${REPO}/releases"
GITHUB_API="https://api.github.com/repos/${REPO}/releases/latest"
cur_dir="$(pwd)"

[[ $EUID -ne 0 ]] && echo -e "${red}错误：${plain} 必须使用 root 用户运行此脚本！\n" && exit 1

detect_os() {
    if [[ -f /etc/redhat-release ]]; then
        release="centos"
    elif cat /etc/issue 2>/dev/null | grep -Eqi "debian"; then
        release="debian"
    elif cat /etc/issue 2>/dev/null | grep -Eqi "ubuntu"; then
        release="ubuntu"
    elif cat /etc/issue 2>/dev/null | grep -Eqi "centos|red hat|redhat"; then
        release="centos"
    elif cat /proc/version 2>/dev/null | grep -Eqi "debian"; then
        release="debian"
    elif cat /proc/version 2>/dev/null | grep -Eqi "ubuntu"; then
        release="ubuntu"
    elif cat /proc/version 2>/dev/null | grep -Eqi "centos|red hat|redhat"; then
        release="centos"
    else
        echo -e "${red}未检测到系统版本，请联系脚本作者！${plain}\n"
        exit 1
    fi

    os_version=""
    if [[ -f /etc/os-release ]]; then
        os_version="$(awk -F'[= ."]' '/VERSION_ID/{print $3}' /etc/os-release | head -n1)"
    fi
    if [[ -z "${os_version}" && -f /etc/lsb-release ]]; then
        os_version="$(awk -F'[= ."]+' '/DISTRIB_RELEASE/{print $2}' /etc/lsb-release | head -n1)"
    fi
    os_version="${os_version:-0}"

    if [[ "${release}" == "centos" ]]; then
        if [[ "${os_version}" -le 6 ]]; then
            echo -e "${red}请使用 CentOS 7 或更高版本的系统！${plain}\n"
            exit 1
        fi
    elif [[ "${release}" == "ubuntu" ]]; then
        if [[ "${os_version}" -lt 16 ]]; then
            echo -e "${red}请使用 Ubuntu 16 或更高版本的系统！${plain}\n"
            exit 1
        fi
    elif [[ "${release}" == "debian" ]]; then
        if [[ "${os_version}" -lt 8 ]]; then
            echo -e "${red}请使用 Debian 8 或更高版本的系统！${plain}\n"
            exit 1
        fi
    fi
}

detect_arch() {
    local a
    a="$(arch)"
    if [[ "$a" == "x86_64" || "$a" == "x64" || "$a" == "amd64" ]]; then
        arch_name="64"
    elif [[ "$a" == "aarch64" || "$a" == "arm64" ]]; then
        arch_name="arm64-v8a"
    elif [[ "$a" == "s390x" ]]; then
        arch_name="s390x"
    else
        arch_name="64"
        echo -e "${yellow}检测架构失败，使用默认架构：${arch_name}${plain}"
    fi

    echo "架构：${arch_name}"

    if [ "$(getconf WORD_BIT)" != "32" ] && [ "$(getconf LONG_BIT)" != "64" ]; then
        echo "本软件不支持 32 位系统(x86)，请使用 64 位系统(x86_64)。如果检测有误，请联系作者。"
        exit 2
    fi
}

install_base() {
    if [[ "${release}" == "centos" ]]; then
        yum install epel-release -y || true
        yum install wget curl unzip tar crontabs socat -y
    else
        apt update -y
        apt install wget curl unzip tar cron socat -y
    fi
}

check_status() {
    if [[ ! -f /etc/systemd/system/XrayR.service ]]; then
        return 2
    fi

    if systemctl is-active --quiet XrayR; then
        return 0
    fi
    return 1
}

get_latest_version() {
    curl -Ls "${GITHUB_API}" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/' | head -n1
}

download_file() {
    local url="$1"
    local output="$2"

    wget -q -N --no-check-certificate -O "${output}" "${url}" || {
        echo -e "${red}下载失败：${url}${plain}"
        exit 1
    }
}

install_XrayR() {
    local last_version url

    if [[ -e /usr/local/XrayR/ ]]; then
        rm -rf /usr/local/XrayR/
    fi

    mkdir -p /usr/local/XrayR/
    cd /usr/local/XrayR/

    if [[ $# -eq 0 || -z "${1:-}" ]]; then
        last_version="$(get_latest_version)"
        if [[ -z "${last_version}" ]]; then
            echo -e "${red}检测 XrayR 最新版本失败，可能是 GitHub API 限制或仓库 release 不存在。请手动指定版本安装。${plain}"
            exit 1
        fi
        echo -e "检测到 XrayR 最新版本：${last_version}，开始安装"
    else
        if [[ "$1" == v* ]]; then
            last_version="$1"
        else
            last_version="v$1"
        fi
        echo -e "开始安装 XrayR ${last_version}"
    fi

    url="${GITHUB_RELEASES}/download/${last_version}/XrayR-linux-${arch_name}.zip"
    download_file "${url}" "/usr/local/XrayR/XrayR-linux.zip"

    unzip -o XrayR-linux.zip
    rm -f XrayR-linux.zip
    chmod +x XrayR

    mkdir -p /etc/XrayR/
    rm -f /etc/systemd/system/XrayR.service

    download_file "${RAW_BASE}/XrayR.service" "/etc/systemd/system/XrayR.service"

    systemctl daemon-reload
    systemctl stop XrayR >/dev/null 2>&1 || true
    systemctl enable XrayR

    echo -e "${green}XrayR ${last_version}${plain} 安装完成，已设置开机自启"

    cp -f geoip.dat /etc/XrayR/ 2>/dev/null || true
    cp -f geosite.dat /etc/XrayR/ 2>/dev/null || true

    if [[ ! -f /etc/XrayR/config.yml ]]; then
        cp -f config.yml /etc/XrayR/ 2>/dev/null || true
        echo -e ""
        echo -e "全新安装，请先参看教程：https://github.com/${REPO}，配置必要的内容。"
    else
        systemctl start XrayR || true
        sleep 2
        echo -e ""
        if check_status; then
            echo -e "${green}XrayR 启动成功${plain}"
        else
            echo -e "${red}XrayR 可能启动失败，请稍后使用 XrayR log 查看日志信息。${plain}"
        fi
    fi

    for f in dns.json route.json custom_outbound.json custom_inbound.json rulelist; do
        if [[ ! -f "/etc/XrayR/${f}" && -f "/usr/local/XrayR/${f}" ]]; then
            cp -f "/usr/local/XrayR/${f}" "/etc/XrayR/${f}"
        fi
    done

    curl -o /usr/bin/XrayR -Ls "${RAW_BASE}/XrayR.sh"
    chmod +x /usr/bin/XrayR

    rm -f /usr/bin/xrayr
    ln -s /usr/bin/XrayR /usr/bin/xrayr
    chmod +x /usr/bin/xrayr

    cd "${cur_dir}"
    rm -f install.sh

    echo -e ""
    echo "XrayR 管理脚本使用方法（兼容 xrayr 小写执行）："
    echo "------------------------------------------"
    echo "XrayR              - 显示管理菜单"
    echo "XrayR start        - 启动 XrayR"
    echo "XrayR stop         - 停止 XrayR"
    echo "XrayR restart      - 重启 XrayR"
    echo "XrayR status       - 查看 XrayR 状态"
    echo "XrayR enable       - 设置 XrayR 开机自启"
    echo "XrayR disable      - 取消 XrayR 开机自启"
    echo "XrayR log          - 查看 XrayR 日志"
    echo "XrayR update       - 更新 XrayR"
    echo "XrayR update x.x.x - 更新 XrayR 指定版本"
    echo "XrayR config       - 显示配置文件内容"
    echo "XrayR install      - 安装 XrayR"
    echo "XrayR uninstall    - 卸载 XrayR"
    echo "XrayR version      - 查看 XrayR 版本"
    echo "------------------------------------------"
}

main() {
    detect_os
    detect_arch
    echo -e "${green}开始安装${plain}"
    install_base
    install_XrayR "${1:-}"
}

main "$@"
