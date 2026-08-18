#!/usr/bin/env bash
set -Eeuo pipefail

if [[ $# -ne 3 ]]; then
    echo "用法：$0 RELEASE_ARCHIVE INSTALL_SCRIPT SOURCE_BINARY" >&2
    exit 2
fi

archive="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
install_script="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"
source_binary="$(cd "$(dirname "$3")" && pwd)/$(basename "$3")"
archive_name="$(basename "${archive}")"
checksum="${archive}.sha256"

for required in "${archive}" "${checksum}" "${install_script}" "${source_binary}"; do
    [[ -f "${required}" ]] || { echo "错误：测试输入不存在：${required}" >&2; exit 1; }
done

test_root="$(mktemp -d)"
trap 'rm -rf "${test_root}"' EXIT
release_root="${test_root}/releases"
mock_systemctl="${test_root}/systemctl"
mkdir -p "${release_root}/v0.9.0-r1"
cp "${archive}" "${release_root}/v0.9.0-r1/${archive_name}"
cp "${checksum}" "${release_root}/v0.9.0-r1/${archive_name}.sha256"

cat > "${mock_systemctl}" <<'MOCK'
#!/usr/bin/env bash
set -u
echo "$*" >> "${OLDXR_SYSTEMCTL_LOG}"
case "${1:-}" in
    is-active)
        [[ -f "${OLDXR_SYSTEMCTL_STATE}" ]]
        ;;
    start)
        if [[ -f "${OLDXR_SYSTEMCTL_FAIL_ONCE}" ]]; then
            rm -f "${OLDXR_SYSTEMCTL_FAIL_ONCE}"
            exit 1
        fi
        touch "${OLDXR_SYSTEMCTL_STATE}"
        ;;
    stop)
        rm -f "${OLDXR_SYSTEMCTL_STATE}"
        ;;
    *)
        exit 0
        ;;
esac
MOCK
chmod +x "${mock_systemctl}"

prepare_layout() {
    local name="$1"
    local source_marker="$2"
    local root="${test_root}/${name}"
    local config_path="/etc/XrayR/config.yml"

    if [[ "${name}" == "statusx7-xr" ]]; then
        config_path="/etc/XrayR/legacy-config.yml"
    fi

    rm -rf "${root}"
    mkdir -p "${root}/usr/local/XrayR" "${root}/etc/XrayR" \
        "${root}/etc/systemd/system" "${root}/usr/bin"
    cp "${source_binary}" "${root}/usr/local/XrayR/XrayR"
    chmod +x "${root}/usr/local/XrayR/XrayR"
    printf '#!/usr/bin/env bash\n# %s\n' "${source_marker}" > "${root}/usr/local/XrayR/XrayR.sh"
    cp "${root}/usr/local/XrayR/XrayR.sh" "${root}/usr/bin/XrayR"
    chmod +x "${root}/usr/bin/XrayR"
    ln -s "${root}/usr/bin/XrayR" "${root}/usr/bin/xrayr"
    cat > "${root}/etc/systemd/system/XrayR.service" <<SERVICE
[Service]
ExecStart=/usr/local/XrayR/XrayR --config ${config_path}
SERVICE
    mkdir -p "$(dirname "${root}${config_path}")"
    printf 'PanelType: "V2board"\nApiKey: "phase3-%s-sentinel"\n' "${name}" > "${root}${config_path}"
    chmod 640 "${root}${config_path}"
    printf '{"sentinel":"%s"}\n' "${name}" > "$(dirname "${root}${config_path}")/custom_inbound.json"

    printf '%s\n' "${config_path}" > "${root}/config-path"
    sha256sum "${root}${config_path}" | awk '{print $1}' > "${root}/config-before"
    sha256sum "${root}/usr/local/XrayR/XrayR" | awk '{print $1}' > "${root}/binary-before"
    sha256sum "${root}/etc/systemd/system/XrayR.service" | awk '{print $1}' > "${root}/service-before"
    sha256sum "${root}/usr/bin/XrayR" | awk '{print $1}' > "${root}/manager-before"
    sha256sum "$(dirname "${root}${config_path}")/custom_inbound.json" | awk '{print $1}' > "${root}/custom-before"
    touch "${root}/systemctl-active"
}

run_installer() {
    local name="$1"
    local root="${test_root}/${name}"
    env \
        OLDXR_RELEASE_BASE="file://${release_root}" \
        OLDXR_INSTALL_ROOT="${root}" \
        OLDXR_SKIP_BASE_INSTALL=1 \
        OLDXR_SYSTEMCTL_BIN="${mock_systemctl}" \
        OLDXR_SYSTEMCTL_STATE="${root}/systemctl-active" \
        OLDXR_SYSTEMCTL_LOG="${root}/systemctl.log" \
        OLDXR_SYSTEMCTL_FAIL_ONCE="${root}/systemctl-fail-once" \
        OLDXR_ARCH=amd64 \
        bash "${install_script}" 0.9.0
}

assert_preserved_upgrade() {
    local name="$1"
    local expected_source="$2"
    local root="${test_root}/${name}"
    local config_path
    local output
    local backup
    config_path="$(<"${root}/config-path")"

    output="$(run_installer "${name}")"
    grep -F "检测到现有安装：来源=${expected_source}" <<<"${output}" >/dev/null
    grep -F "检测到配置：${config_path}" <<<"${output}" >/dev/null
    grep -F "配置已保留：${config_path}" <<<"${output}" >/dev/null
    [[ "$(<"${root}/config-before")" == "$(sha256sum "${root}${config_path}" | awk '{print $1}')" ]]
    [[ "$(stat -c '%a' "${root}${config_path}")" == "640" ]]
    [[ "$(<"${root}/custom-before")" == "$(sha256sum "$(dirname "${root}${config_path}")/custom_inbound.json" | awk '{print $1}')" ]]
    grep -Fx "ExecStart=/usr/local/XrayR/XrayR --config ${config_path}" "${root}/etc/systemd/system/XrayR.service" >/dev/null
    [[ -f "${root}/usr/local/XrayR/.oldxr-release" ]]
    grep -Fx 'v0.9.0-r1' "${root}/usr/local/XrayR/.oldxr-release" >/dev/null
    [[ -f "${root}/systemctl-active" ]]

    backup="$(find "${root}/etc/XrayR/backups" -mindepth 1 -maxdepth 1 -type d | sort | tail -n 1)"
    [[ -n "${backup}" && -f "${backup}/manifest" ]]
    grep -F "config_path=${config_path}" "${backup}/manifest" >/dev/null
    grep -F "config_sha256=$(<"${root}/config-before")" "${backup}/manifest" >/dev/null
    [[ -f "${backup}/install/XrayR" ]]
    [[ -f "${backup}/system/XrayR.service" ]]
    [[ -f "${backup}/config/config.yml" ]]
    [[ -f "${backup}/config/custom/custom_inbound.json" ]]
}

echo "执行 official XrayR v0.9.0 布局升级测试"
prepare_layout official 'https://github.com/XrayR-project/XrayR'
assert_preserved_upgrade official 'official XrayR'

echo "执行 statusX7/XR legacy 布局升级测试"
prepare_layout statusx7-xr 'https://github.com/statusX7/XR'
assert_preserved_upgrade statusx7-xr 'statusX7/XR legacy'

echo "执行 oldxr v0.9.0-r1 布局升级测试"
prepare_layout oldxr-r1 'https://github.com/statusX7/oldxr'
printf 'v0.9.0-r1\n' > "${test_root}/oldxr-r1/usr/local/XrayR/.oldxr-release"
assert_preserved_upgrade oldxr-r1 oldxr

echo "执行 service 启动失败回滚测试"
prepare_layout rollback 'https://github.com/XrayR-project/XrayR'
touch "${test_root}/rollback/systemctl-fail-once"
if run_installer rollback >/dev/null 2>&1; then
    echo "错误：service 启动失败时安装脚本未返回失败。" >&2
    exit 1
fi
rollback_config="$(<"${test_root}/rollback/config-path")"
[[ "$(<"${test_root}/rollback/config-before")" == "$(sha256sum "${test_root}/rollback${rollback_config}" | awk '{print $1}')" ]]
[[ "$(<"${test_root}/rollback/binary-before")" == "$(sha256sum "${test_root}/rollback/usr/local/XrayR/XrayR" | awk '{print $1}')" ]]
[[ "$(<"${test_root}/rollback/service-before")" == "$(sha256sum "${test_root}/rollback/etc/systemd/system/XrayR.service" | awk '{print $1}')" ]]
[[ "$(<"${test_root}/rollback/manager-before")" == "$(sha256sum "${test_root}/rollback/usr/bin/XrayR" | awk '{print $1}')" ]]
[[ "$(<"${test_root}/rollback/custom-before")" == "$(sha256sum "${test_root}/rollback/etc/XrayR/custom_inbound.json" | awk '{print $1}')" ]]
[[ -f "${test_root}/rollback/systemctl-active" ]]
[[ ! -e "${test_root}/rollback/usr/local/XrayR/.oldxr-release" ]]
for absent_after_rollback in custom_outbound.json route.json dns.json rulelist geoip.dat geosite.dat; do
    [[ ! -e "${test_root}/rollback/etc/XrayR/${absent_after_rollback}" ]]
done

echo "PASS：三类历史布局均保留配置与自定义文件，持久备份和 service 失败回滚有效。"
