#!/usr/bin/env bash
set -Eeuo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
test_root="$(mktemp -d)"
trap 'rm -rf "${test_root}"' EXIT

mock_systemctl="${test_root}/systemctl"
systemctl_log="${test_root}/systemctl.log"
cat > "${mock_systemctl}" <<'MOCK'
#!/usr/bin/env bash
set -u
echo "$*" >> "${OLDXR_SYSTEMCTL_LOG}"
case "${1:-}" in
    is-active|is-enabled)
        exit 0
        ;;
    *)
        exit 0
        ;;
esac
MOCK
chmod +x "${mock_systemctl}"

run_menu() {
    local selection="$1"
    printf '%s\n' "${selection}" | env \
        OLDXR_INSTALL_ROOT="${test_root}/root" \
        OLDXR_SYSTEMCTL_BIN="${mock_systemctl}" \
        OLDXR_SYSTEMCTL_LOG="${systemctl_log}" \
        bash "${repo_root}/XrayR.sh" 2>&1
}

strip_colors() {
    local value="$1"
    value="${value//$'\033[0;31m'/}"
    value="${value//$'\033[0;32m'/}"
    value="${value//$'\033[0;33m'/}"
    value="${value//$'\033[0m'/}"
    printf '%s\n' "${value}"
}

set +e
menu_output="$(run_menu 99)"
menu_status=$?
set -e
[[ ${menu_status} -eq 2 ]]
plain_output="$(strip_colors "${menu_output}")"

expected_lines=(
    "  XrayR 后端管理脚本，不适用于docker"
    "--- https://github.com/statusX7/oldxr ---"
    "  0. 修改配置"
    "  1. 安装 XrayR"
    "  2. 更新 XrayR"
    "  3. 卸载 XrayR"
    "  4. 启动 XrayR"
    "  5. 停止 XrayR"
    "  6. 重启 XrayR"
    "  7. 查看 XrayR 状态"
    "  8. 查看 XrayR 日志"
    "  9. 设置 XrayR 开机自启"
    " 10. 取消 XrayR 开机自启"
    " 11. 一键安装 bbr (最新内核)"
    " 12. 查看 XrayR 版本"
    " 13. 升级维护脚本"
    "XrayR状态: 未安装"
)
for expected in "${expected_lines[@]}"; do
    grep -Fx -- "${expected}" <<<"${plain_output}" >/dev/null || {
        echo "错误：管理菜单缺少原版布局行：${expected}" >&2
        exit 1
    }
done

mkdir -p "${test_root}/root/etc/systemd/system" "${test_root}/root/usr/local/XrayR"
touch "${test_root}/root/etc/systemd/system/XrayR.service"
printf '#!/usr/bin/env bash\nexit 0\n' > "${test_root}/root/usr/local/XrayR/XrayR"
chmod +x "${test_root}/root/usr/local/XrayR/XrayR"

set +e
menu_output="$(run_menu 99)"
menu_status=$?
set -e
[[ ${menu_status} -eq 2 ]]
plain_output="$(strip_colors "${menu_output}")"
grep -Fx 'XrayR状态: 已运行' <<<"${plain_output}" >/dev/null
grep -Fx '是否开机自启: 是' <<<"${plain_output}" >/dev/null

: > "${systemctl_log}"
run_menu 4 >/dev/null
grep -Fx 'start XrayR' "${systemctl_log}" >/dev/null

bbr_output="$(run_menu 11)"
grep -F '不会自动运行已归档的第三方内核脚本' <<<"${bbr_output}" >/dev/null

grep -F 'version="v1.0.1"' "${repo_root}/XrayR.sh" >/dev/null
echo "PASS：v1.0.1 管理脚本采用原版 v0.9.0 菜单布局，状态展示与菜单路由通过。"
