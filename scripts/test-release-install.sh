#!/usr/bin/env bash
set -Eeuo pipefail

if [[ $# -ne 2 ]]; then
    echo "用法：$0 RELEASE_ARCHIVE INSTALL_SCRIPT" >&2
    exit 2
fi

archive="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
install_script="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"
repo_root="$(cd "$(dirname "${install_script}")" && pwd)"
default_config="${repo_root}/main/config.yml.example"
archive_name="$(basename "${archive}")"
checksum="${archive}.sha256"
release_version="$(sed -n 's/^CURRENT_V1="\([^"]*\)"/\1/p' "${install_script}")"

if [[ ! "${release_version}" =~ ^v1\.0\.[0-9]+$ ]]; then
    echo "错误：无法从 install.sh 解析 v1.0.x Release。" >&2
    exit 1
fi
for required in "${archive}" "${checksum}" "${install_script}" "${default_config}"; do
    [[ -f "${required}" ]] || { echo "错误：测试输入不存在：${required}" >&2; exit 1; }
done

test_root="$(mktemp -d)"
trap 'rm -rf "${test_root}"' EXIT
release_root="${test_root}/releases"
raw_root="${test_root}/raw"
install_root="${test_root}/root"
systemctl_state="${test_root}/systemctl-active"
systemctl_log="${test_root}/systemctl.log"
mock_systemctl="${test_root}/systemctl"
pristine_archive="${test_root}/${archive_name}.pristine"

mkdir -p "${release_root}/${release_version}" "${raw_root}" "${install_root}"
cp "${archive}" "${release_root}/${release_version}/${archive_name}"
cp "${checksum}" "${release_root}/${release_version}/${archive_name}.sha256"
cp "${archive}" "${pristine_archive}"
cp "${install_script}" "${raw_root}/install.sh"

cat > "${mock_systemctl}" <<'MOCK'
#!/usr/bin/env bash
set -u
echo "$*" >> "${OLDXR_SYSTEMCTL_LOG}"
case "${1:-}" in
    is-active)
        [[ -f "${OLDXR_SYSTEMCTL_STATE}" ]]
        ;;
    start|restart)
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

bad_config="${test_root}/bad-default-config.yml"
bad_install_root="${test_root}/bad-config-root"
cp "${default_config}" "${bad_config}"
printf '\n# CHECKSUM-MISMATCH\n' >> "${bad_config}"
echo "执行新装默认配置 checksum 停服前保护"
if env \
    OLDXR_RELEASE_BASE="file://${release_root}" \
    OLDXR_DEFAULT_CONFIG_URL="file://${bad_config}" \
    OLDXR_INSTALL_ROOT="${bad_install_root}" \
    OLDXR_SKIP_BASE_INSTALL=1 \
    OLDXR_HEALTH_WAIT_SECONDS=0 \
    OLDXR_SYSTEMCTL_BIN="${mock_systemctl}" \
    OLDXR_SYSTEMCTL_STATE="${test_root}/bad-config-systemctl-active" \
    OLDXR_SYSTEMCTL_LOG="${test_root}/bad-config-systemctl.log" \
    OLDXR_ARCH=amd64 \
    bash "${install_script}" "${release_version#v}" >/dev/null 2>&1; then
    echo "错误：被篡改的新装默认配置未被 SHA256 拒绝。" >&2
    exit 1
fi
[[ ! -e "${bad_install_root}/usr/local/XrayR" ]]
if [[ -f "${test_root}/bad-config-systemctl.log" ]] && grep -Fx "stop XrayR" "${test_root}/bad-config-systemctl.log" >/dev/null; then
    echo "错误：默认配置校验失败后服务已被停止。" >&2
    exit 1
fi

run_installer() {
    env \
        OLDXR_RELEASE_BASE="file://${release_root}" \
        OLDXR_DEFAULT_CONFIG_URL="file://${default_config}" \
        OLDXR_INSTALL_ROOT="${install_root}" \
        OLDXR_SKIP_BASE_INSTALL=1 \
        OLDXR_HEALTH_WAIT_SECONDS=0 \
        OLDXR_SYSTEMCTL_BIN="${mock_systemctl}" \
        OLDXR_SYSTEMCTL_STATE="${systemctl_state}" \
        OLDXR_SYSTEMCTL_LOG="${systemctl_log}" \
        OLDXR_ARCH=amd64 \
        bash "${install_script}" "$@"
}

echo "执行 ${release_version} 单二进制 fresh install"
fresh_output="$(run_installer "${release_version#v}")"
grep -F "目标 oldxr 版本：${release_version}" <<<"${fresh_output}" >/dev/null
grep -F "oldxr ${release_version} 安装完成" <<<"${fresh_output}" >/dev/null

for required in \
    usr/local/XrayR/XrayR \
    usr/local/XrayR/XrayR.sh \
    usr/local/XrayR/config.yml \
    usr/local/XrayR/geoip.dat \
    usr/local/XrayR/geosite.dat \
    usr/local/XrayR/XrayR.service \
    etc/XrayR/config.yml \
    etc/XrayR/geoip.dat \
    etc/XrayR/geosite.dat \
    etc/systemd/system/XrayR.service \
    usr/bin/XrayR; do
    [[ -f "${install_root}/${required}" ]] || { echo "错误：fresh install 缺少 ${required}" >&2; exit 1; }
done
for forbidden in XrayR-fastengine XrayR-legacy FASTENGINE-LICENSE FASTENGINE-NOTICE.md; do
    [[ ! -e "${install_root}/usr/local/XrayR/${forbidden}" ]] || {
        echo "错误：v1 archive/安装目录仍包含 ${forbidden}" >&2
        exit 1
    }
done
[[ -x "${install_root}/usr/local/XrayR/XrayR" ]]
[[ -x "${install_root}/usr/bin/XrayR" ]]
[[ -L "${install_root}/usr/bin/xrayr" ]]
"${install_root}/usr/local/XrayR/XrayR" -version | grep -F "XrayR ${release_version#v}" >/dev/null
grep -Fx "WorkingDirectory=/usr/local/XrayR/" "${install_root}/etc/systemd/system/XrayR.service" >/dev/null
grep -Fx "ExecStart=/usr/local/XrayR/XrayR --config /etc/XrayR/config.yml" "${install_root}/etc/systemd/system/XrayR.service" >/dev/null
grep -Fx "daemon-reload" "${systemctl_log}" >/dev/null
grep -Fx "enable XrayR" "${systemctl_log}" >/dev/null
if grep -Fx "start XrayR" "${systemctl_log}" >/dev/null; then
    echo "错误：fresh install 在用户确认配置前不应启动 service。" >&2
    exit 1
fi

cmp -s "${default_config}" "${install_root}/etc/XrayR/config.yml" || {
    echo "错误：fresh install 未采用固定的新装默认配置。" >&2
    exit 1
}

printf '\n# USER-PRESERVED-SENTINEL\n' >> "${install_root}/etc/XrayR/config.yml"
config_hash_before="$(sha256sum "${install_root}/etc/XrayR/config.yml" | awk '{print $1}')"
touch "${systemctl_state}"
echo "执行 ${release_version} 事务更新"
update_output="$(run_installer "${release_version}")"
grep -F "XrayR service 已启动" <<<"${update_output}" >/dev/null
grep -F "可回滚备份：" <<<"${update_output}" >/dev/null
[[ "${config_hash_before}" == "$(sha256sum "${install_root}/etc/XrayR/config.yml" | awk '{print $1}')" ]]
backup_dir="$(find "${install_root}/etc/XrayR/backups" -mindepth 1 -maxdepth 1 -type d | sort | tail -n 1)"
[[ -f "${backup_dir}/install-dir/XrayR" ]]
[[ -f "${backup_dir}/system/XrayR.service" ]]
grep -F "target=${release_version}" "${backup_dir}/manifest" >/dev/null

echo "执行管理脚本默认版本更新"
manager_output="$(env \
    OLDXR_RAW_BASE="file://${raw_root}" \
    OLDXR_RELEASE_BASE="file://${release_root}" \
    OLDXR_INSTALL_ROOT="${install_root}" \
    OLDXR_SKIP_BASE_INSTALL=1 \
    OLDXR_SKIP_INSTALL_CHECK=1 \
    OLDXR_HEALTH_WAIT_SECONDS=0 \
    OLDXR_SYSTEMCTL_BIN="${mock_systemctl}" \
    OLDXR_SYSTEMCTL_STATE="${systemctl_state}" \
    OLDXR_SYSTEMCTL_LOG="${systemctl_log}" \
    OLDXR_ARCH=amd64 \
    bash "${install_root}/usr/bin/XrayR" update)"
grep -F "更新完成" <<<"${manager_output}" >/dev/null

echo "执行 checksum 失败停服前保护"
binary_hash_before="$(sha256sum "${install_root}/usr/local/XrayR/XrayR" | awk '{print $1}')"
stop_count_before="$(grep -c '^stop XrayR$' "${systemctl_log}" || true)"
printf 'corrupt' >> "${release_root}/${release_version}/${archive_name}"
if run_installer "${release_version#v}" >/dev/null 2>&1; then
    echo "错误：损坏的 archive 未被 checksum 拒绝。" >&2
    exit 1
fi
[[ "${binary_hash_before}" == "$(sha256sum "${install_root}/usr/local/XrayR/XrayR" | awk '{print $1}')" ]]
stop_count_after="$(grep -c '^stop XrayR$' "${systemctl_log}" || true)"
[[ "${stop_count_before}" == "${stop_count_after}" ]] || {
    echo "错误：checksum 失败后服务已被停止。" >&2
    exit 1
}
cp "${pristine_archive}" "${release_root}/${release_version}/${archive_name}"

if run_installer 0.9.0 >/dev/null 2>&1; then
    echo "错误：旧 0.9.0 maintenance 参数未被拒绝。" >&2
    exit 1
fi

echo "PASS：${release_version} 单二进制 fresh install、update、备份、manager、systemd 与 checksum pre-stop Gate 均通过。"
