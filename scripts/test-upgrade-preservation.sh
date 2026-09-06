#!/usr/bin/env bash
set -Eeuo pipefail

if [[ $# -lt 3 ]]; then
    echo "用法：$0 RELEASE_ARCHIVE INSTALL_SCRIPT OFFICIAL_V0_9_0_BINARY [OLDXR_V1_BINARY ...]" >&2
    exit 2
fi

archive="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
install_script="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"
official_binary="$(cd "$(dirname "$3")" && pwd)/$(basename "$3")"
oldxr_binaries=()
if [[ $# -gt 3 ]]; then
    for input_binary in "${@:4}"; do
        oldxr_binaries+=("$(cd "$(dirname "${input_binary}")" && pwd)/$(basename "${input_binary}")")
    done
fi
archive_name="$(basename "${archive}")"
checksum="${archive}.sha256"
release_version="$(sed -n 's/^CURRENT_V1="\([^"]*\)"/\1/p' "${install_script}")"

if [[ ! "${release_version}" =~ ^v1\.[0-9]+\.[0-9]+$ ]]; then
    echo "错误：无法从 install.sh 解析 v1.x Release。" >&2
    exit 1
fi
for required in "${archive}" "${checksum}" "${install_script}" "${official_binary}"; do
    [[ -f "${required}" ]] || { echo "错误：测试输入不存在：${required}" >&2; exit 1; }
done
"${official_binary}" -version | grep -F 'XrayR 0.9.0' >/dev/null || {
    echo "错误：输入 binary 不是 exact official XrayR v0.9.0。" >&2
    exit 1
}
for oldxr_binary in "${oldxr_binaries[@]}"; do
    [[ -f "${oldxr_binary}" ]] || { echo "错误：oldxr v1 binary 不存在：${oldxr_binary}" >&2; exit 1; }
    "${oldxr_binary}" -version | grep -E '^XrayR 1\.[0-9]+\.[0-9]+' >/dev/null || {
        echo "错误：输入 binary 不是 oldxr v1.x。" >&2
        exit 1
    }
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

logical_to_file() {
    local root="$1"
    local logical="$2"
    printf '%s%s\n' "${root}" "${logical}"
}

write_user_fixture() {
    local root="$1"
    local logical="$2"
    local contents="$3"
    local target
    target="$(logical_to_file "${root}" "${logical}")"
    mkdir -p "$(dirname "${target}")"
    printf '%s\n' "${contents}" > "${target}"
    chmod 640 "${target}"
}

record_file() {
    local root="$1"
    local logical="$2"
    local key="$3"
    local target
    target="$(logical_to_file "${root}" "${logical}")"
    printf '%s\n' "$(sha256sum "${target}" | awk '{print $1}')" > "${root}/${key}.sha"
    printf '%s\n' "$(stat -c '%u:%g' "${target}")" > "${root}/${key}.owner"
    printf '%s\n' "$(stat -c '%a' "${target}")" > "${root}/${key}.mode"
}

assert_file_preserved() {
    local root="$1"
    local logical="$2"
    local key="$3"
    local target
    target="$(logical_to_file "${root}" "${logical}")"
    [[ "$(<"${root}/${key}.sha")" == "$(sha256sum "${target}" | awk '{print $1}')" ]]
    [[ "$(<"${root}/${key}.owner")" == "$(stat -c '%u:%g' "${target}")" ]]
    [[ "$(<"${root}/${key}.mode")" == "$(stat -c '%a' "${target}")" ]]
}

prepare_official_layout() {
    local name="$1"
    local config_style="$2"
    local root="${test_root}/${name}"
    local config_path="/srv/oldxr-${name}/config.yml"
    local config_dir="/srv/oldxr-${name}"
    local exec_args

    case "${config_style}" in
        space) exec_args="--config ${config_path}" ;;
        equals) exec_args="--config=${config_path}" ;;
        short) exec_args="-config ${config_path}" ;;
        *) return 2 ;;
    esac

    mkdir -p "${root}/usr/local/XrayR" "${root}/etc/systemd/system" "${root}/usr/bin"
    cp "${official_binary}" "${root}/usr/local/XrayR/XrayR"
    chmod +x "${root}/usr/local/XrayR/XrayR"
    cat > "${root}/usr/bin/XrayR" <<'MANAGER'
#!/usr/bin/env bash
# https://github.com/XrayR-project/XrayR
MANAGER
    chmod +x "${root}/usr/bin/XrayR"
    ln -s /usr/bin/XrayR "${root}/usr/bin/xrayr"
    cat > "${root}/etc/systemd/system/XrayR.service" <<SERVICE
[Unit]
Description=Official XrayR
[Service]
ExecStart=/usr/local/XrayR/XrayR ${exec_args}
SERVICE

    write_user_fixture "${root}" "${config_dir}/route.json" '{"sentinel":"route"}'
    write_user_fixture "${root}" "${config_dir}/custom_outbound.json" '[{"tag":"IPv4_out","protocol":"freedom"}]'
    write_user_fixture "${root}" "${config_dir}/custom_inbound.json" '[]'
    write_user_fixture "${root}" "${config_dir}/dns.json" '{"servers":["localhost"]}'
    write_user_fixture "${root}" "${config_dir}/rulelist" 'regexp:example.invalid'
    write_user_fixture "${root}" "${config_dir}/cert/node.cert" 'CERTIFICATE-SENTINEL'
    write_user_fixture "${root}" "${config_dir}/cert/node.key" 'PRIVATE-KEY-SENTINEL'
    write_user_fixture "${root}" "${config_path}" "$(cat <<CONFIG
Log:
  Level: none
DnsConfigPath: ${config_dir}/dns.json
RouteConfigPath: ${config_dir}/route.json
InboundConfigPath: ${config_dir}/custom_inbound.json
OutboundConfigPath: ${config_dir}/custom_outbound.json
Nodes:
  - PanelType: V2board
    ApiConfig:
      ApiHost: https://example.invalid
      ApiKey: SENTINEL
      NodeID: 11
      NodeType: V2ray
      RuleListPath: ${config_dir}/rulelist
    ControllerConfig:
      CertConfig:
        CertMode: file
        CertFile: ${config_dir}/cert/node.cert
        KeyFile: ${config_dir}/cert/node.key
CONFIG
)"

    for key_path in \
        config:"${config_path}" \
        route:"${config_dir}/route.json" \
        outbound:"${config_dir}/custom_outbound.json" \
        inbound:"${config_dir}/custom_inbound.json" \
        dns:"${config_dir}/dns.json" \
        rulelist:"${config_dir}/rulelist" \
        cert:"${config_dir}/cert/node.cert" \
        key:"${config_dir}/cert/node.key"; do
        record_file "${root}" "${key_path#*:}" "${key_path%%:*}"
    done
    sha256sum "${root}/usr/local/XrayR/XrayR" | awk '{print $1}' > "${root}/binary.sha"
    sha256sum "${root}/etc/systemd/system/XrayR.service" | awk '{print $1}' > "${root}/service.sha"
    sha256sum "${root}/usr/bin/XrayR" | awk '{print $1}' > "${root}/manager.sha"
    printf '%s\n' "${config_path}" > "${root}/config-path"
    touch "${root}/systemctl-active"
}

prepare_oldxr_layout() {
    local name="$1"
    local config_style="$2"
    local source_binary="$3"
    local root="${test_root}/${name}"

    prepare_official_layout "${name}" "${config_style}"
    cp "${source_binary}" "${root}/usr/local/XrayR/XrayR"
    chmod +x "${root}/usr/local/XrayR/XrayR"
    "${source_binary}" -version | sed -nE 's/^XrayR ([0-9]+\.[0-9]+\.[0-9]+).*/v\1/p' > "${root}/usr/local/XrayR/.oldxr-release"
    cat > "${root}/usr/bin/XrayR" <<'MANAGER'
#!/usr/bin/env bash
# https://github.com/statusX7/oldxr
MANAGER
    chmod +x "${root}/usr/bin/XrayR"
    sha256sum "${root}/usr/local/XrayR/XrayR" | awk '{print $1}' > "${root}/binary.sha"
    sha256sum "${root}/usr/bin/XrayR" | awk '{print $1}' > "${root}/manager.sha"
}

run_installer() {
    local name="$1"
    shift
    local root="${test_root}/${name}"
    env \
        OLDXR_RELEASE_BASE="file://${release_root}" \
        OLDXR_INSTALL_ROOT="${root}" \
        OLDXR_SKIP_BASE_INSTALL=1 \
        OLDXR_HEALTH_WAIT_SECONDS=0 \
        OLDXR_SYSTEMCTL_BIN="${mock_systemctl}" \
        OLDXR_SYSTEMCTL_STATE="${root}/systemctl-active" \
        OLDXR_SYSTEMCTL_LOG="${root}/systemctl.log" \
        OLDXR_SYSTEMCTL_FAIL_ONCE="${root}/systemctl-fail-once" \
        OLDXR_ARCH=amd64 \
        bash "${install_script}" "$@"
}

assert_successful_upgrade() {
    local name="$1"
    local expected_source="${2:-official XrayR}"
    local root="${test_root}/${name}"
    local config_path
    local config_dir
    local output
    local backup

    config_path="$(<"${root}/config-path")"
    config_dir="$(dirname "${config_path}")"
    output="$(run_installer "${name}" "${release_version#v}")"
    grep -F "检测到现有安装：来源=${expected_source}" <<<"${output}" >/dev/null
    grep -F "检测到配置：${config_path}" <<<"${output}" >/dev/null
    grep -F 'XrayR service 已启动' <<<"${output}" >/dev/null
    grep -Fx "ExecStart=/usr/local/XrayR/XrayR --config ${config_path}" "${root}/etc/systemd/system/XrayR.service" >/dev/null
    for key_path in \
        config:"${config_path}" \
        route:"${config_dir}/route.json" \
        outbound:"${config_dir}/custom_outbound.json" \
        inbound:"${config_dir}/custom_inbound.json" \
        dns:"${config_dir}/dns.json" \
        rulelist:"${config_dir}/rulelist" \
        cert:"${config_dir}/cert/node.cert" \
        key:"${config_dir}/cert/node.key"; do
        assert_file_preserved "${root}" "${key_path#*:}" "${key_path%%:*}"
    done
    [[ -f "${root}/usr/local/XrayR/.oldxr-release" ]]
    grep -Fx "${release_version}" "${root}/usr/local/XrayR/.oldxr-release" >/dev/null
    "${root}/usr/local/XrayR/XrayR" -version | grep -F "XrayR ${release_version#v}" >/dev/null
    [[ ! -e "${root}/usr/local/XrayR/XrayR-fastengine" ]]
    [[ ! -e "${root}/usr/local/XrayR/XrayR-legacy" ]]
    [[ -f "${root}/systemctl-active" ]]

    backup="$(find "${root}/etc/XrayR/backups" -mindepth 1 -maxdepth 1 -type d | sort | tail -n 1)"
    [[ -f "${backup}/install-dir/XrayR" ]]
    [[ -f "${backup}/system/XrayR.service" ]]
    [[ -f "${backup}/files${config_path}" ]]
    [[ -f "${backup}/files${config_dir}/cert/node.key" ]]
    grep -F "config_path=${config_path}" "${backup}/manifest" >/dev/null
}

echo "执行官方 v0.9.0 --config 非默认路径升级"
prepare_official_layout official-space space
assert_successful_upgrade official-space

echo "执行官方 v0.9.0 --config= 非默认路径升级"
prepare_official_layout official-equals equals
assert_successful_upgrade official-equals

echo "执行官方 v0.9.0 -config 非默认路径升级"
prepare_official_layout official-short short
assert_successful_upgrade official-short

oldxr_index=0
for oldxr_binary in "${oldxr_binaries[@]}"; do
    oldxr_index=$((oldxr_index + 1))
    oldxr_version="$("${oldxr_binary}" -version | sed -nE 's/^XrayR ([0-9]+\.[0-9]+\.[0-9]+).*/\1/p')"
    echo "执行现有 oldxr ${oldxr_version} 非默认配置路径升级"
    prepare_oldxr_layout "oldxr-v1-${oldxr_index}" space "${oldxr_binary}"
    assert_successful_upgrade "oldxr-v1-${oldxr_index}" oldxr
done

echo "执行 service 启动失败自动回滚"
prepare_official_layout rollback space
touch "${test_root}/rollback/systemctl-fail-once"
if run_installer rollback "${release_version#v}" >/dev/null 2>&1; then
    echo "错误：service 启动失败时安装器未返回失败。" >&2
    exit 1
fi
rollback_root="${test_root}/rollback"
rollback_config="$(<"${rollback_root}/config-path")"
rollback_dir="$(dirname "${rollback_config}")"
[[ "$(<"${rollback_root}/binary.sha")" == "$(sha256sum "${rollback_root}/usr/local/XrayR/XrayR" | awk '{print $1}')" ]]
[[ "$(<"${rollback_root}/service.sha")" == "$(sha256sum "${rollback_root}/etc/systemd/system/XrayR.service" | awk '{print $1}')" ]]
[[ "$(<"${rollback_root}/manager.sha")" == "$(sha256sum "${rollback_root}/usr/bin/XrayR" | awk '{print $1}')" ]]
for key_path in \
    config:"${rollback_config}" \
    route:"${rollback_dir}/route.json" \
    outbound:"${rollback_dir}/custom_outbound.json" \
    inbound:"${rollback_dir}/custom_inbound.json" \
    dns:"${rollback_dir}/dns.json" \
    rulelist:"${rollback_dir}/rulelist" \
    cert:"${rollback_dir}/cert/node.cert" \
    key:"${rollback_dir}/cert/node.key"; do
    assert_file_preserved "${rollback_root}" "${key_path#*:}" "${key_path%%:*}"
done
[[ -f "${rollback_root}/systemctl-active" ]]
[[ ! -e "${rollback_root}/usr/local/XrayR/.oldxr-release" ]]
[[ ! -e "${rollback_root}${rollback_dir}/geoip.dat" ]]
[[ ! -e "${rollback_root}${rollback_dir}/geosite.dat" ]]

if [[ ${#oldxr_binaries[@]} -gt 0 ]]; then
    echo "PASS：官方 XrayR v0.9.0 三种 config flag 与 oldxr v1.x 均无损升级，用户文件元数据、永久备份及启动失败自动回滚通过。"
else
    echo "PASS：官方 XrayR v0.9.0 三种 config flag 布局均无损升级，用户文件元数据与永久备份完整，启动失败自动回滚通过。"
fi
