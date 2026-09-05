#!/usr/bin/env bash
set -Eeuo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
test_root="$(mktemp -d)"
trap 'rm -rf -- "${test_root}"' EXIT

for requested in 1.1.0 v1.1.0; do
    set +e
    output="$(env OLDXR_INSTALL_ROOT="${test_root}/root" \
        OLDXR_SKIP_BASE_INSTALL=1 OLDXR_SYSTEMCTL_BIN=false \
        OLDXR_RELEASE_BASE="file://${test_root}/no-release" \
        bash "${repo_root}/install.sh" "${requested}" 2>&1)"
    status=$?
    set -e
    [[ ${status} -eq 2 ]]
    grep -F 'v1.1.0 暂停提供安装' <<<"${output}" >/dev/null
    if grep -F '目标 oldxr 版本：' <<<"${output}" >/dev/null; then
        echo '错误：已撤回版本不能静默替换成其他版本。' >&2
        exit 1
    fi
    [[ ! -e "${test_root}/root" ]]
done

echo 'PASS：撤回版本在下载、服务操作与文件修改前明确拒绝，没有静默替换。'
