#!/usr/bin/env bash
set -Eeuo pipefail
export TZ=UTC

if [[ $# -lt 5 || $# -gt 6 ]]; then
    echo "用法：$0 GOOS GOARCH GOARM ASSET_NAME VERSION [OUTPUT_DIR]" >&2
    exit 2
fi

target_os="$1"
target_arch="$2"
target_arm="$3"
asset_name="$4"
release_version="$5"
output_dir="${6:-dist}"
go_bin="${GO_BIN:-go}"

if [[ "${target_os}" != "linux" || ! "${target_arch}" =~ ^(amd64|arm64)$ ]]; then
    echo "错误：oldxr v1.x Release 仅支持 linux/amd64 与 linux/arm64。" >&2
    exit 2
fi
if [[ -n "${target_arm}" ]]; then
    echo "错误：linux/amd64 与 linux/arm64 不应设置 GOARM。" >&2
    exit 2
fi
if [[ ! "${asset_name}" =~ ^[A-Za-z0-9._-]+$ ]]; then
    echo "错误：无效的 asset name。" >&2
    exit 2
fi
if [[ ! "${release_version}" =~ ^v?1\.[0-9]+\.[0-9]+$ ]]; then
    echo "错误：版本必须匹配 v1.x.y。" >&2
    exit 2
fi
for tool in "${go_bin}" file readelf zip sha256sum; do
    command -v "${tool}" >/dev/null 2>&1 || {
        echo "错误：构建工具不存在：${tool}" >&2
        exit 1
    }
done

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
mkdir -p "${output_dir}"
output_dir="$(cd "${output_dir}" && pwd)"
stage_root="$(mktemp -d)"
trap 'rm -rf "${stage_root}"' EXIT
stage_dir="${stage_root}/build_assets"
mkdir -p "${stage_dir}"

version_value="${release_version#v}"
build_env=(
    CGO_ENABLED=0
    GOOS="${target_os}"
    GOARCH="${target_arch}"
    GOFLAGS=-buildvcs=false
)
if [[ "${target_arch}" == "amd64" ]]; then
    build_env+=(GOAMD64=v1)
fi

echo "构建 ${target_os}/${target_arch} -> XrayR-${asset_name}.zip"
(
    cd "${repo_root}"
    env "${build_env[@]}" "${go_bin}" build \
        -trimpath \
        -buildvcs=false \
        -ldflags "-s -w -buildid= -X main.version=${version_value}" \
        -o "${stage_dir}/XrayR" ./main
)

if readelf -l "${stage_dir}/XrayR" | grep -q 'INTERP'; then
    echo "错误：XrayR Release 不应依赖动态 ELF interpreter。" >&2
    exit 1
fi
if readelf -d "${stage_dir}/XrayR" 2>/dev/null | grep -q '(NEEDED)'; then
    echo "错误：XrayR Release 仍包含动态 shared-library 依赖。" >&2
    exit 1
fi
echo "XrayR ELF：$(file -b "${stage_dir}/XrayR")"

for source in \
    README.md \
    LICENSE \
    XrayR.service \
    XrayR.sh \
    main/dns.json \
    main/route.json \
    main/custom_outbound.json \
    main/custom_inbound.json \
    main/rulelist \
    main/config.yml.example \
    main/geoip.dat \
    main/geosite.dat; do
    if [[ ! -f "${repo_root}/${source}" ]]; then
        echo "错误：Release 必需文件不存在：${source}" >&2
        exit 1
    fi
done

cp "${repo_root}/README.md" "${stage_dir}/README.md"
cp "${repo_root}/LICENSE" "${stage_dir}/LICENSE"
cp "${repo_root}/XrayR.service" "${stage_dir}/XrayR.service"
cp "${repo_root}/XrayR.sh" "${stage_dir}/XrayR.sh"
cp "${repo_root}/main/dns.json" "${stage_dir}/dns.json"
cp "${repo_root}/main/route.json" "${stage_dir}/route.json"
cp "${repo_root}/main/custom_outbound.json" "${stage_dir}/custom_outbound.json"
cp "${repo_root}/main/custom_inbound.json" "${stage_dir}/custom_inbound.json"
cp "${repo_root}/main/rulelist" "${stage_dir}/rulelist"
cp "${repo_root}/main/config.yml.example" "${stage_dir}/config.yml"
cp "${repo_root}/main/geoip.dat" "${stage_dir}/geoip.dat"
cp "${repo_root}/main/geosite.dat" "${stage_dir}/geosite.dat"
chmod +x "${stage_dir}/XrayR" "${stage_dir}/XrayR.sh"

source_date_epoch="${SOURCE_DATE_EPOCH:-$(git -C "${repo_root}" show -s --format=%ct HEAD)}"
find "${stage_dir}" -type f -exec touch -d "@${source_date_epoch}" {} +

archive_name="XrayR-${asset_name}.zip"
archive_path="${output_dir}/${archive_name}"
rm -f "${archive_path}" "${archive_path}.sha256"
(
    cd "${stage_dir}"
    LC_ALL=C find . -maxdepth 1 -type f -printf '%P\n' | LC_ALL=C sort | zip -9X "${archive_path}" -@
)
(
    cd "${output_dir}"
    sha256sum "${archive_name}" > "${archive_name}.sha256"
)

echo "Release asset：${archive_path}"
echo "SHA256：$(awk '{print $1}' "${archive_path}.sha256")"
