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
        if [[ -n "${OLDXR_SYSTEMCTL_FAIL_ONCE:-}" && -f "${OLDXR_SYSTEMCTL_FAIL_ONCE}" ]]; then
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

prepare_known_connectivity_default() {
    local root="$1"
    local installed_version="${2:-v1.0.2}"
    local handshake="${3:-4}"
    local idle="${4:-30}"
    local uplink="${5:-2}"
    local downlink="${6:-4}"
    local buffer="${7:-64}"
    mkdir -p "${root}/usr/local/XrayR" "${root}/etc/XrayR" "${root}/etc/systemd/system" "${root}/usr/bin"
    cat > "${root}/usr/local/XrayR/XrayR" <<OLD_BINARY
#!/usr/bin/env bash
echo 'XrayR ${installed_version#v}'
OLD_BINARY
    chmod +x "${root}/usr/local/XrayR/XrayR"
    printf '%s\n' "${installed_version}" > "${root}/usr/local/XrayR/.oldxr-release"
    cat > "${root}/usr/bin/XrayR" <<'OLD_MANAGER'
#!/usr/bin/env bash
# statusX7/oldxr
OLD_MANAGER
    chmod +x "${root}/usr/bin/XrayR"
    ln -s /usr/bin/XrayR "${root}/usr/bin/xrayr"
    cat > "${root}/etc/systemd/system/XrayR.service" <<'OLD_SERVICE'
[Service]
ExecStart=/usr/local/XrayR/XrayR --config /etc/XrayR/config.yml
OLD_SERVICE
    cat > "${root}/etc/XrayR/config.yml" <<OLD_CONFIG
# known oldxr connectivity default
ConnectionConfig:
  Handshake: ${handshake} # legacy
  ConnIdle: ${idle} # legacy
  UplinkOnly: ${uplink} # legacy
  DownlinkOnly: ${downlink} # legacy
  BufferSize: ${buffer} # legacy
Nodes:
  - PanelType: V2board
    ApiConfig:
      ApiHost: https://user-preserved.invalid
      ApiKey: USER-PRESERVED
      NodeID: 41
      NodeType: V2ray
      Timeout: 5 # user value must remain unchanged
    ControllerConfig:
      CertConfig:
        CertMode: none
OLD_CONFIG
    printf '{"sentinel":"route-preserved"}\n' > "${root}/etc/XrayR/route.json"
    chmod 640 "${root}/etc/XrayR/config.yml" "${root}/etc/XrayR/route.json"
    touch "${root}/systemctl-active"
}

run_connectivity_migration() {
    local root="$1"
    local fail_once="${2:-}"
    env \
        OLDXR_RELEASE_BASE="file://${release_root}" \
        OLDXR_DEFAULT_CONFIG_URL="file://${test_root}/must-not-be-downloaded" \
        OLDXR_INSTALL_ROOT="${root}" \
        OLDXR_SKIP_BASE_INSTALL=1 \
        OLDXR_HEALTH_WAIT_SECONDS=0 \
        OLDXR_SYSTEMCTL_BIN="${mock_systemctl}" \
        OLDXR_SYSTEMCTL_STATE="${root}/systemctl-active" \
        OLDXR_SYSTEMCTL_LOG="${root}/systemctl.log" \
        OLDXR_SYSTEMCTL_FAIL_ONCE="${fail_once}" \
        OLDXR_ARCH=amd64 \
        bash "${install_script}" "${release_version#v}"
}

echo "执行v1.0.2旧默认连接参数定向迁移"
migration_root="${test_root}/migration-root"
prepare_known_connectivity_default "${migration_root}"
migration_mode_before="$(stat -c '%a' "${migration_root}/etc/XrayR/config.yml")"
migration_owner_before="$(stat -c '%u:%g' "${migration_root}/etc/XrayR/config.yml")"
route_hash_before="$(sha256sum "${migration_root}/etc/XrayR/route.json" | awk '{print $1}')"
migration_output="$(run_connectivity_migration "${migration_root}")"
grep -F '已将v1.0.2-source-default连接参数迁移为v1.0.3稳定值' <<<"${migration_output}" >/dev/null
grep -Eq '^[[:space:]]*Handshake:[[:space:]]*8([[:space:]]|$)' "${migration_root}/etc/XrayR/config.yml"
grep -Eq '^[[:space:]]*ConnIdle:[[:space:]]*21600([[:space:]]|$)' "${migration_root}/etc/XrayR/config.yml"
grep -Eq '^[[:space:]]*UplinkOnly:[[:space:]]*300([[:space:]]|$)' "${migration_root}/etc/XrayR/config.yml"
grep -Eq '^[[:space:]]*DownlinkOnly:[[:space:]]*300([[:space:]]|$)' "${migration_root}/etc/XrayR/config.yml"
grep -Eq '^[[:space:]]*BufferSize:[[:space:]]*256([[:space:]]|$)' "${migration_root}/etc/XrayR/config.yml"
grep -Eq '^[[:space:]]{6}Timeout:[[:space:]]*5([[:space:]]|$)' "${migration_root}/etc/XrayR/config.yml"
grep -F 'ApiKey: USER-PRESERVED' "${migration_root}/etc/XrayR/config.yml" >/dev/null
[[ "${migration_mode_before}" == "$(stat -c '%a' "${migration_root}/etc/XrayR/config.yml")" ]]
[[ "${migration_owner_before}" == "$(stat -c '%u:%g' "${migration_root}/etc/XrayR/config.yml")" ]]
[[ "${route_hash_before}" == "$(sha256sum "${migration_root}/etc/XrayR/route.json" | awk '{print $1}')" ]]
migration_backup="$(find "${migration_root}/etc/XrayR/backups" -mindepth 1 -maxdepth 1 -type d | sort | tail -n 1)"
grep -Eq '^[[:space:]]*ConnIdle:[[:space:]]*30([[:space:]]|$)' "${migration_backup}/files/etc/XrayR/config.yml"

echo "执行v1.0.2安装器旧默认连接参数定向迁移"
migration_installer_root="${test_root}/migration-installer-root"
prepare_known_connectivity_default "${migration_installer_root}" v1.0.2 4 120 0 0 8
migration_installer_output="$(run_connectivity_migration "${migration_installer_root}")"
grep -F '已将v1.0.2-installer-default连接参数迁移为v1.0.3稳定值' <<<"${migration_installer_output}" >/dev/null
grep -Eq '^[[:space:]]*UplinkOnly:[[:space:]]*300([[:space:]]|$)' "${migration_installer_root}/etc/XrayR/config.yml"

echo "执行既有v1.0.3默认连接参数替换迁移"
migration_v103_root="${test_root}/migration-v103-root"
prepare_known_connectivity_default "${migration_v103_root}" v1.0.3 8 21600 2 4 256
migration_v103_output="$(run_connectivity_migration "${migration_v103_root}")"
grep -F '已将v1.0.3-prior-default连接参数迁移为v1.0.3稳定值' <<<"${migration_v103_output}" >/dev/null
grep -Eq '^[[:space:]]*UplinkOnly:[[:space:]]*300([[:space:]]|$)' "${migration_v103_root}/etc/XrayR/config.yml"
grep -Eq '^[[:space:]]*DownlinkOnly:[[:space:]]*300([[:space:]]|$)' "${migration_v103_root}/etc/XrayR/config.yml"

echo "执行v1.0.2自定义配置不迁移保护"
migration_custom_root="${test_root}/migration-custom-root"
prepare_known_connectivity_default "${migration_custom_root}"
sed -i -E 's/^([[:space:]]*ConnIdle:)[[:space:]]*30/\1 31/' "${migration_custom_root}/etc/XrayR/config.yml"
migration_custom_hash="$(sha256sum "${migration_custom_root}/etc/XrayR/config.yml" | awk '{print $1}')"
run_connectivity_migration "${migration_custom_root}" >/dev/null
[[ "${migration_custom_hash}" == "$(sha256sum "${migration_custom_root}/etc/XrayR/config.yml" | awk '{print $1}')" ]]

echo "执行v1.0.2迁移后启动失败自动回滚"
migration_rollback_root="${test_root}/migration-rollback-root"
prepare_known_connectivity_default "${migration_rollback_root}"
migration_hash_before="$(sha256sum "${migration_rollback_root}/etc/XrayR/config.yml" | awk '{print $1}')"
touch "${migration_rollback_root}/fail-once"
if run_connectivity_migration "${migration_rollback_root}" "${migration_rollback_root}/fail-once" >/dev/null 2>&1; then
    echo "错误：迁移后启动失败未触发回滚。" >&2
    exit 1
fi
[[ "${migration_hash_before}" == "$(sha256sum "${migration_rollback_root}/etc/XrayR/config.yml" | awk '{print $1}')" ]]
grep -Fx 'v1.0.2' "${migration_rollback_root}/usr/local/XrayR/.oldxr-release" >/dev/null
[[ -f "${migration_rollback_root}/systemctl-active" ]]

if run_installer 0.9.0 >/dev/null 2>&1; then
    echo "错误：旧 0.9.0 maintenance 参数未被拒绝。" >&2
    exit 1
fi

echo "PASS：${release_version} 单二进制 fresh install、update、备份、manager、systemd 与 checksum pre-stop Gate 均通过。"
