#!/usr/bin/env bash
set -Eeuo pipefail

if [[ $# -ne 2 ]]; then
    echo "用法：$0 RELEASE_ARCHIVE INSTALL_SCRIPT" >&2
    exit 2
fi

archive="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
install_script="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"
archive_name="$(basename "${archive}")"
checksum="${archive}.sha256"
release_version="$(sed -n 's/^MAINTENANCE_0_9_0="\([^"]*\)"/\1/p' "${install_script}")"

if [[ ! "${release_version}" =~ ^v0\.9\.0-r[0-9]+$ ]]; then
    echo "错误：无法从 install.sh 解析 maintenance release。" >&2
    exit 1
fi

[[ -f "${archive}" ]] || { echo "错误：archive 不存在：${archive}" >&2; exit 1; }
[[ -f "${checksum}" ]] || { echo "错误：checksum 不存在：${checksum}" >&2; exit 1; }
[[ -f "${install_script}" ]] || { echo "错误：install.sh 不存在：${install_script}" >&2; exit 1; }

test_root="$(mktemp -d)"
trap 'rm -rf "${test_root}"' EXIT
release_root="${test_root}/releases"
raw_root="${test_root}/raw"
install_root="${test_root}/root"
systemctl_state="${test_root}/systemctl-active"
systemctl_log="${test_root}/systemctl.log"
mock_systemctl="${test_root}/systemctl"

mkdir -p "${release_root}/${release_version}" "${raw_root}" "${install_root}"
cp "${archive}" "${release_root}/${release_version}/${archive_name}"
cp "${checksum}" "${release_root}/${release_version}/${archive_name}.sha256"
cp "${install_script}" "${raw_root}/install.sh"

cat > "${mock_systemctl}" <<'MOCK'
#!/usr/bin/env bash
set -u
echo "$*" >> "${OLDXR_SYSTEMCTL_LOG}"
case "${1:-}" in
    is-active)
        [[ -f "${OLDXR_SYSTEMCTL_STATE}" ]]
        ;;
    start)
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

run_installer() {
    env \
        OLDXR_RELEASE_BASE="file://${release_root}" \
        OLDXR_INSTALL_ROOT="${install_root}" \
        OLDXR_SKIP_BASE_INSTALL=1 \
        OLDXR_SYSTEMCTL_BIN="${mock_systemctl}" \
        OLDXR_SYSTEMCTL_STATE="${systemctl_state}" \
        OLDXR_SYSTEMCTL_LOG="${systemctl_log}" \
        OLDXR_ARCH=amd64 \
        bash "${install_script}" "$@"
}

echo "执行 fresh install channel test"
fresh_output="$(run_installer 0.9.0)"
grep -F "maintenance channel 0.9.0 当前解析为 ${release_version}" <<<"${fresh_output}" >/dev/null
grep -F "oldxr ${release_version} 安装完成" <<<"${fresh_output}" >/dev/null

for required in \
    usr/local/XrayR/XrayR \
    usr/local/XrayR/config.yml \
    usr/local/XrayR/geoip.dat \
    usr/local/XrayR/geosite.dat \
    usr/local/XrayR/XrayR.service \
    usr/local/XrayR/XrayR.sh \
    etc/XrayR/config.yml \
    etc/XrayR/geoip.dat \
    etc/XrayR/geosite.dat \
    etc/systemd/system/XrayR.service \
    usr/bin/XrayR; do
    [[ -f "${install_root}/${required}" ]] || { echo "错误：fresh install 缺少 ${required}" >&2; exit 1; }
done
[[ -L "${install_root}/usr/bin/xrayr" ]] || { echo "错误：缺少 xrayr symlink" >&2; exit 1; }
"${install_root}/usr/local/XrayR/XrayR" -version | grep -F "XrayR ${release_version#v}" >/dev/null
grep -Fx "daemon-reload" "${systemctl_log}" >/dev/null
grep -Fx "enable XrayR" "${systemctl_log}" >/dev/null
if grep -Fx "start XrayR" "${systemctl_log}" >/dev/null; then
    echo "错误：fresh install 在用户配置前不应启动 service" >&2
    exit 1
fi
grep -Fx "WorkingDirectory=/usr/local/XrayR/" "${install_root}/etc/systemd/system/XrayR.service" >/dev/null
grep -Fx "ExecStart=/usr/local/XrayR/XrayR --config /etc/XrayR/config.yml" "${install_root}/etc/systemd/system/XrayR.service" >/dev/null

config_hash_before="$(sha256sum "${install_root}/etc/XrayR/config.yml" | awk '{print $1}')"
echo "执行 update test"
update_output="$(run_installer "${release_version}")"
grep -F "使用显式 maintenance release：${release_version}" <<<"${update_output}" >/dev/null
grep -F "XrayR service 已启动" <<<"${update_output}" >/dev/null
config_hash_after="$(sha256sum "${install_root}/etc/XrayR/config.yml" | awk '{print $1}')"
[[ "${config_hash_before}" == "${config_hash_after}" ]] || { echo "错误：update 覆盖了 config.yml" >&2; exit 1; }
grep -Fx "start XrayR" "${systemctl_log}" >/dev/null

echo "执行 XrayR.sh update channel test"
manager_output="$(env \
    OLDXR_RAW_BASE="file://${raw_root}" \
    OLDXR_RELEASE_BASE="file://${release_root}" \
    OLDXR_INSTALL_ROOT="${install_root}" \
    OLDXR_SKIP_BASE_INSTALL=1 \
    OLDXR_SKIP_INSTALL_CHECK=1 \
    OLDXR_SYSTEMCTL_BIN="${mock_systemctl}" \
    OLDXR_SYSTEMCTL_STATE="${systemctl_state}" \
    OLDXR_SYSTEMCTL_LOG="${systemctl_log}" \
    OLDXR_ARCH=amd64 \
    bash "${install_root}/usr/bin/XrayR" update 0.9.0)"
grep -F "maintenance channel 0.9.0 当前解析为 ${release_version}" <<<"${manager_output}" >/dev/null
grep -F "更新完成" <<<"${manager_output}" >/dev/null

echo "执行 checksum failure preservation test"
installed_hash_before="$(sha256sum "${install_root}/usr/local/XrayR/XrayR" | awk '{print $1}')"
printf 'corrupt' >> "${release_root}/${release_version}/${archive_name}"
if run_installer 0.9.0 >/dev/null 2>&1; then
    echo "错误：损坏 archive 未被 checksum 拒绝" >&2
    exit 1
fi
installed_hash_after="$(sha256sum "${install_root}/usr/local/XrayR/XrayR" | awk '{print $1}')"
[[ "${installed_hash_before}" == "${installed_hash_after}" ]] || { echo "错误：checksum 失败后已安装 binary 被修改" >&2; exit 1; }

if run_installer 0.9.1 >/dev/null 2>&1; then
    echo "错误：不兼容版本参数 0.9.1 未被拒绝" >&2
    exit 1
fi

echo "PASS：fresh install、update、config preservation、systemd wiring 与 checksum failure 均符合预期。"
