#!/usr/bin/env bash
set -Eeuo pipefail

if [[ $# -lt 3 || $# -gt 7 ]]; then
    echo "用法：$0 RELEASE_ARCHIVE INSTALL_SCRIPT OFFICIAL_BINARY [STATUSX7_XR_BINARY] [OLDXR_R1_BINARY] [OLDXR_R2_BINARY] [OLDXR_R3_BINARY]" >&2
    exit 2
fi

archive="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
install_script="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"
source_binary="$(cd "$(dirname "$3")" && pwd)/$(basename "$3")"
statusx7_binary="${4:-${source_binary}}"
oldxr_r1_binary="${5:-${source_binary}}"
oldxr_r2_binary="${6:-${source_binary}}"
oldxr_r3_binary="${7:-${source_binary}}"
statusx7_binary="$(cd "$(dirname "${statusx7_binary}")" && pwd)/$(basename "${statusx7_binary}")"
oldxr_r1_binary="$(cd "$(dirname "${oldxr_r1_binary}")" && pwd)/$(basename "${oldxr_r1_binary}")"
oldxr_r2_binary="$(cd "$(dirname "${oldxr_r2_binary}")" && pwd)/$(basename "${oldxr_r2_binary}")"
oldxr_r3_binary="$(cd "$(dirname "${oldxr_r3_binary}")" && pwd)/$(basename "${oldxr_r3_binary}")"
archive_name="$(basename "${archive}")"
checksum="${archive}.sha256"
release_version="$(sed -n 's/^MAINTENANCE_0_9_0="\([^"]*\)"/\1/p' "${install_script}")"

if [[ ! "${release_version}" =~ ^v0\.9\.0-r[0-9]+$ ]]; then
    echo "错误：无法从 install.sh 解析 maintenance release。" >&2
    exit 1
fi

for required in "${archive}" "${checksum}" "${install_script}" "${source_binary}" "${statusx7_binary}" "${oldxr_r1_binary}" "${oldxr_r2_binary}" "${oldxr_r3_binary}"; do
    [[ -f "${required}" ]] || { echo "错误：测试输入不存在：${required}" >&2; exit 1; }
done

test_root="$(mktemp -d)"
trap 'rm -rf "${test_root}"' EXIT
release_root="${test_root}/releases"
mock_systemctl="${test_root}/systemctl"
mkdir -p "${release_root}/${release_version}"
cp "${archive}" "${release_root}/${release_version}/${archive_name}"
cp "${checksum}" "${release_root}/${release_version}/${archive_name}.sha256"

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
    local layout_binary="$3"
    local root="${test_root}/${name}"
    local config_path="/etc/XrayR/config.yml"

    if [[ "${name}" == "statusx7-xr" ]]; then
        config_path="/etc/XrayR/legacy-config.yml"
    fi

    rm -rf "${root}"
    mkdir -p "${root}/usr/local/XrayR" "${root}/etc/XrayR" \
        "${root}/etc/systemd/system" "${root}/usr/bin"
    cp "${layout_binary}" "${root}/usr/local/XrayR/XrayR"
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
    for custom_file in custom_inbound.json custom_outbound.json route.json dns.json rulelist; do
        printf '{"sentinel":"%s-%s"}\n' "${name}" "${custom_file}" > "$(dirname "${root}${config_path}")/${custom_file}"
        sha256sum "$(dirname "${root}${config_path}")/${custom_file}" | awk '{print $1}' > "${root}/${custom_file}-before"
    done

    printf '%s\n' "${config_path}" > "${root}/config-path"
    sha256sum "${root}${config_path}" | awk '{print $1}' > "${root}/config-before"
    stat -c '%u:%g' "${root}${config_path}" > "${root}/config-owner-before"
    sha256sum "${root}/usr/local/XrayR/XrayR" | awk '{print $1}' > "${root}/binary-before"
    "${root}/usr/local/XrayR/XrayR" -version | sed -n '1p' > "${root}/version-before"
    sha256sum "${root}/etc/systemd/system/XrayR.service" | awk '{print $1}' > "${root}/service-before"
    sha256sum "${root}/usr/bin/XrayR" | awk '{print $1}' > "${root}/manager-before"
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
    [[ "$(<"${root}/config-owner-before")" == "$(stat -c '%u:%g' "${root}${config_path}")" ]]
    for custom_file in custom_inbound.json custom_outbound.json route.json dns.json rulelist; do
        [[ "$(<"${root}/${custom_file}-before")" == "$(sha256sum "$(dirname "${root}${config_path}")/${custom_file}" | awk '{print $1}')" ]]
    done
    grep -Fx "ExecStart=/usr/local/XrayR/XrayR --config ${config_path}" "${root}/etc/systemd/system/XrayR.service" >/dev/null
    [[ -f "${root}/usr/local/XrayR/.oldxr-release" ]]
    [[ -x "${root}/usr/local/XrayR/XrayR-fastengine" ]]
    [[ -x "${root}/usr/local/XrayR/XrayR-legacy" ]]
    grep -Fx "${release_version}" "${root}/usr/local/XrayR/.oldxr-release" >/dev/null
    "${root}/usr/local/XrayR/XrayR" -version | grep -F "XrayR ${release_version#v}" >/dev/null
    [[ -f "${root}/systemctl-active" ]]

    backup="$(find "${root}/etc/XrayR/backups" -mindepth 1 -maxdepth 1 -type d | sort | tail -n 1)"
    [[ -n "${backup}" && -f "${backup}/manifest" ]]
    grep -F "config_path=${config_path}" "${backup}/manifest" >/dev/null
    grep -F "config_sha256=$(<"${root}/config-before")" "${backup}/manifest" >/dev/null
    grep -F "version=$(<"${root}/version-before")" "${backup}/manifest" >/dev/null
    [[ -f "${backup}/install/XrayR" ]]
    [[ -f "${backup}/system/XrayR.service" ]]
    [[ -f "${backup}/config/config.yml" ]]
    for custom_file in custom_inbound.json custom_outbound.json route.json dns.json rulelist; do
        [[ -f "${backup}/config/custom/${custom_file}" ]]
    done
}

echo "执行 official XrayR v0.9.0 布局升级测试"
prepare_layout official 'https://github.com/XrayR-project/XrayR' "${source_binary}"
assert_preserved_upgrade official 'official XrayR'

echo "执行 statusX7/XR legacy 布局升级测试"
prepare_layout statusx7-xr 'https://github.com/statusX7/XR' "${statusx7_binary}"
assert_preserved_upgrade statusx7-xr 'statusX7/XR legacy'

echo "执行 oldxr v0.9.0-r1 布局升级测试"
prepare_layout oldxr-r1 'https://github.com/statusX7/oldxr' "${oldxr_r1_binary}"
printf 'v0.9.0-r1\n' > "${test_root}/oldxr-r1/usr/local/XrayR/.oldxr-release"
printf 'v0.9.0-r1\n' > "${test_root}/oldxr-r1/version-before"
assert_preserved_upgrade oldxr-r1 oldxr

echo "执行 oldxr v0.9.0-r2 布局升级测试"
prepare_layout oldxr-r2 'https://github.com/statusX7/oldxr' "${oldxr_r2_binary}"
printf 'v0.9.0-r2\n' > "${test_root}/oldxr-r2/usr/local/XrayR/.oldxr-release"
printf 'v0.9.0-r2\n' > "${test_root}/oldxr-r2/version-before"
assert_preserved_upgrade oldxr-r2 oldxr

echo "执行 oldxr v0.9.0-r3 布局升级测试"
prepare_layout oldxr-r3 'https://github.com/statusX7/oldxr' "${oldxr_r3_binary}"
printf 'v0.9.0-r3\n' > "${test_root}/oldxr-r3/usr/local/XrayR/.oldxr-release"
printf 'v0.9.0-r3\n' > "${test_root}/oldxr-r3/version-before"
assert_preserved_upgrade oldxr-r3 oldxr

echo "执行 service 启动失败回滚测试"
prepare_layout rollback 'https://github.com/XrayR-project/XrayR' "${source_binary}"
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
for custom_file in custom_inbound.json custom_outbound.json route.json dns.json rulelist; do
    [[ "$(<"${test_root}/rollback/${custom_file}-before")" == "$(sha256sum "${test_root}/rollback/etc/XrayR/${custom_file}" | awk '{print $1}')" ]]
done
[[ -f "${test_root}/rollback/systemctl-active" ]]
[[ ! -e "${test_root}/rollback/usr/local/XrayR/.oldxr-release" ]]
[[ ! -e "${test_root}/rollback/usr/local/XrayR/XrayR-fastengine" ]]
[[ ! -e "${test_root}/rollback/usr/local/XrayR/XrayR-legacy" ]]
for absent_after_rollback in geoip.dat geosite.dat; do
    [[ ! -e "${test_root}/rollback/etc/XrayR/${absent_after_rollback}" ]]
done

echo "PASS：official、statusX7/XR、r1、r2、r3 五类历史布局均保留配置与全部自定义文件，持久备份和 service 失败回滚有效。"
