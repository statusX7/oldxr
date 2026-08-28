#!/usr/bin/env bash
set -Eeuo pipefail

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'

version="v1.0.1"
repo="statusX7/oldxr"
stable_branch="master"
raw_base="${OLDXR_RAW_BASE:-https://raw.githubusercontent.com/${repo}/${stable_branch}}"
install_url="${raw_base}/install.sh"
install_root="${OLDXR_INSTALL_ROOT:-}"
systemctl_bin="${OLDXR_SYSTEMCTL_BIN:-systemctl}"
service_file="${OLDXR_SERVICE_FILE:-${install_root}/etc/systemd/system/XrayR.service}"
binary_file="${OLDXR_BINARY_FILE:-${install_root}/usr/local/XrayR/XrayR}"
manager_file="${OLDXR_MANAGER_FILE:-${install_root}/usr/bin/XrayR}"
manager_link="${OLDXR_MANAGER_LINK:-${install_root}/usr/bin/xrayr}"

[[ ${EUID} -ne 0 ]] && echo -e "${red}错误：${plain}必须使用 root 用户运行此脚本！" && exit 1

run_systemctl() {
    "${systemctl_bin}" "$@"
}

check_status() {
    [[ -f "${service_file}" ]] || return 2
    run_systemctl is-active --quiet XrayR
}

check_install() {
    if [[ "${OLDXR_SKIP_INSTALL_CHECK:-0}" == "1" ]]; then
        return 0
    fi
    if [[ ! -x "${binary_file}" || ! -f "${service_file}" ]]; then
        echo -e "${red}XrayR 尚未安装。${plain}" >&2
        return 1
    fi
}

run_installer() {
    local installer_file
    local status
    installer_file="$(mktemp)"
    if ! curl --fail --location --silent --show-error --retry 3 --output "${installer_file}" "${install_url}"; then
        rm -f -- "${installer_file}"
        echo -e "${red}下载安装脚本失败：${install_url}${plain}" >&2
        return 1
    fi
    if bash "${installer_file}" "$@"; then
        status=0
    else
        status=$?
    fi
    rm -f -- "${installer_file}"
    return "${status}"
}

install_xrayr() {
    run_installer "${1:-${version#v}}"
}

update_xrayr() {
    local requested="${1:-${version#v}}"
    if run_installer "${requested}"; then
        echo -e "${green}更新完成；服务状态已由事务安装器验证。${plain}"
    else
        echo -e "${red}更新失败；事务安装器已尝试恢复原安装。${plain}" >&2
        return 1
    fi
}

start_xrayr() {
    check_install
    run_systemctl start XrayR
    if check_status; then
        echo -e "${green}XrayR 启动成功。${plain}"
    else
        echo -e "${red}XrayR 启动失败，请使用 XrayR log 查看日志。${plain}" >&2
        return 1
    fi
}

stop_xrayr() {
    check_install
    run_systemctl stop XrayR
    if check_status; then
        echo -e "${red}XrayR 停止失败。${plain}" >&2
        return 1
    fi
    echo -e "${green}XrayR 已停止。${plain}"
}

restart_xrayr() {
    check_install
    run_systemctl restart XrayR
    if check_status; then
        echo -e "${green}XrayR 重启成功。${plain}"
    else
        echo -e "${red}XrayR 重启失败，请使用 XrayR log 查看日志。${plain}" >&2
        return 1
    fi
}

show_status() {
    local status
    if check_status; then
        status=0
    else
        status=$?
    fi
    case "${status}" in
        0)
            echo -e "XrayR状态: ${green}已运行${plain}"
            show_enable_status
            ;;
        2)
            echo -e "XrayR状态: ${red}未安装${plain}"
            ;;
        *)
            echo -e "XrayR状态: ${yellow}未运行${plain}"
            show_enable_status
            ;;
    esac
}

show_enable_status() {
    if run_systemctl is-enabled --quiet XrayR; then
        echo -e "是否开机自启: ${green}是${plain}"
    else
        echo -e "是否开机自启: ${red}否${plain}"
    fi
}

show_service_status() {
    check_install
    run_systemctl status XrayR --no-pager -l
}

enable_xrayr() {
    check_install
    run_systemctl enable XrayR
    echo -e "${green}已启用 XrayR 开机启动。${plain}"
}

disable_xrayr() {
    check_install
    run_systemctl disable XrayR
    echo -e "${green}已禁用 XrayR 开机启动。${plain}"
}

show_log() {
    check_install
    journalctl -u XrayR.service -e --no-pager -f
}

show_version() {
    check_install
    "${binary_file}" -version
}

detect_config_path() {
    local exec_start
    local detected
    exec_start="$(sed -n 's/^[[:space:]]*ExecStart=//p' "${service_file}" | head -n 1)"
    detected="$(sed -n \
        -e 's/.*--config[=[:space:]]\([^[:space:]]*\).*/\1/p' \
        -e 's/.*-config[=[:space:]]\([^[:space:]]*\).*/\1/p' \
        <<<"${exec_start}" | head -n 1)"
    detected="${detected#\"}"
    detected="${detected%\"}"
    printf '%s\n' "${detected:-/etc/XrayR/config.yml}"
}

edit_config() {
    local config_path
    local editor
    check_install
    config_path="$(detect_config_path)"
    editor="${EDITOR:-vi}"
    "${editor}" "${config_path}"
    echo "配置已保存；请执行 XrayR restart 使修改生效。"
}

update_shell() {
    local temporary
    temporary="$(mktemp)"
    if ! curl --fail --location --silent --show-error --retry 3 --output "${temporary}" "${raw_base}/XrayR.sh"; then
        rm -f -- "${temporary}"
        echo -e "${red}下载管理脚本失败。${plain}" >&2
        return 1
    fi
    bash -n "${temporary}"
    install -m 0755 "${temporary}" "${manager_file}"
    rm -f -- "${temporary}"
    echo -e "${green}管理脚本升级完成。${plain}"
}

install_bbr() {
    echo -e "${yellow}已保留原版 v0.9.0 的 BBR 菜单入口，但不会自动运行已归档的第三方内核脚本。${plain}"
    echo "请使用当前发行版官方内核与系统工具启用 BBR。"
}

uninstall_xrayr() {
    local answer
    read -r -p "确定卸载 XrayR 并删除 /etc/XrayR 吗？[y/N]: " answer
    [[ "${answer}" == "y" || "${answer}" == "Y" ]] || {
        echo "已取消。"
        return 0
    }
    run_systemctl stop XrayR >/dev/null 2>&1 || true
    run_systemctl disable XrayR >/dev/null 2>&1 || true
    rm -f -- "${service_file}" "${manager_file}" "${manager_link}"
    rm -rf -- "${install_root}/usr/local/XrayR" "${install_root}/etc/XrayR"
    run_systemctl daemon-reload
    echo -e "${green}XrayR 已卸载。${plain}"
}

show_usage() {
    cat <<'USAGE'
XrayR 管理命令：
  XrayR install [1.0.x]
  XrayR update [1.0.x]
  XrayR start|stop|restart|status|log
  XrayR enable|disable
  XrayR config|version|update_shell|uninstall
USAGE
}

show_menu() {
    local choice
    echo -e "
  ${green}XrayR 后端管理脚本，${plain}${red}不适用于docker${plain}
--- https://github.com/statusX7/oldxr ---
  ${green}0.${plain} 修改配置
————————————————
  ${green}1.${plain} 安装 XrayR
  ${green}2.${plain} 更新 XrayR
  ${green}3.${plain} 卸载 XrayR
————————————————
  ${green}4.${plain} 启动 XrayR
  ${green}5.${plain} 停止 XrayR
  ${green}6.${plain} 重启 XrayR
  ${green}7.${plain} 查看 XrayR 状态
  ${green}8.${plain} 查看 XrayR 日志
————————————————
  ${green}9.${plain} 设置 XrayR 开机自启
 ${green}10.${plain} 取消 XrayR 开机自启
————————————————
 ${green}11.${plain} 一键安装 bbr (最新内核)
 ${green}12.${plain} 查看 XrayR 版本
 ${green}13.${plain} 升级维护脚本
"
    show_status
    echo
    read -r -p "请输入选择 [0-13]: " choice
    case "${choice}" in
        0) edit_config ;;
        1) install_xrayr "${version#v}" ;;
        2) update_xrayr "${version#v}" ;;
        3) uninstall_xrayr ;;
        4) start_xrayr ;;
        5) stop_xrayr ;;
        6) restart_xrayr ;;
        7) show_service_status ;;
        8) show_log ;;
        9) enable_xrayr ;;
        10) disable_xrayr ;;
        11) install_bbr ;;
        12) show_version ;;
        13) update_shell ;;
        *) echo -e "${red}请输入正确的数字 [0-13]${plain}" >&2; return 2 ;;
    esac
}

case "${1:-}" in
    "") show_menu ;;
    install) install_xrayr "${2:-${version#v}}" ;;
    update) check_install; update_xrayr "${2:-${version#v}}" ;;
    start) start_xrayr ;;
    stop) stop_xrayr ;;
    restart) restart_xrayr ;;
    status) show_service_status ;;
    enable) enable_xrayr ;;
    disable) disable_xrayr ;;
    log) show_log ;;
    config) edit_config ;;
    version) show_version ;;
    update_shell) update_shell ;;
    uninstall) check_install; uninstall_xrayr ;;
    help|-h|--help) show_usage ;;
    *) show_usage; exit 2 ;;
esac
