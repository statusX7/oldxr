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
legacy_go_bin="${LEGACY_GO_BIN:-${GO_BIN:-go}}"
control_go_bin="${CONTROL_GO_BIN:-${GO_BIN:-go}}"
cargo_bin="${CARGO_BIN:-cargo}"

if [[ "${target_os}" != "linux" || ! "${target_arch}" =~ ^(amd64|arm64)$ ]]; then
    echo "错误：FastEngine Release 当前只支持 linux/amd64 与 linux/arm64。" >&2
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
if [[ ! "${release_version}" =~ ^v?0\.9\.0-r[0-9]+$ ]]; then
    echo "错误：维护版本必须匹配 v0.9.0-rN。" >&2
    exit 2
fi

for tool in "${legacy_go_bin}" "${control_go_bin}" "${cargo_bin}" zip sha256sum; do
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
cargo_target_dir="${CARGO_TARGET_DIR:-${stage_root}/cargo-target}"
mkdir -p "${stage_dir}" "${cargo_target_dir}"

case "${target_arch}" in
    amd64)
        rust_target="x86_64-unknown-linux-gnu"
        rust_binary_dir="${cargo_target_dir}/release"
        ;;
    arm64)
        rust_target="aarch64-unknown-linux-gnu"
        rust_binary_dir="${cargo_target_dir}/${rust_target}/release"
        cross_cc="${AARCH64_CC:-aarch64-linux-gnu-gcc}"
        command -v "${cross_cc}" >/dev/null 2>&1 || {
            echo "错误：arm64 FastEngine 交叉编译器不存在：${cross_cc}" >&2
            exit 1
        }
        ;;
esac

version_value="${release_version#v}"
legacy_build_flags=(-trimpath -buildvcs=false -ldflags "-s -w -buildid= -X main.version=${version_value}")
control_build_flags=(-trimpath -buildvcs=false -ldflags "-s -w -buildid= -X main.version=${version_value}")

echo "构建 ${target_os}/${target_arch} -> XrayR-${asset_name}.zip"
(
    cd "${repo_root}"
    env \
        CGO_ENABLED=0 \
        GOOS="${target_os}" \
        GOARCH="${target_arch}" \
        "${legacy_go_bin}" build "${legacy_build_flags[@]}" \
        -o "${stage_dir}/XrayR-legacy" ./main
)
(
    cd "${repo_root}/fastengine/control"
    env \
        CGO_ENABLED=0 \
        GOOS="${target_os}" \
        GOARCH="${target_arch}" \
        "${control_go_bin}" build "${control_build_flags[@]}" \
        -o "${stage_dir}/XrayR" ./cmd/fastengine-control
)
(
    cd "${repo_root}/fastengine"
    if [[ "${target_arch}" == "arm64" ]]; then
        env \
            CARGO_TARGET_DIR="${cargo_target_dir}" \
            CC_aarch64_unknown_linux_gnu="${cross_cc}" \
            CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER="${cross_cc}" \
            "${cargo_bin}" build --release --locked --target "${rust_target}"
    else
        env CARGO_TARGET_DIR="${cargo_target_dir}" \
            "${cargo_bin}" build --release --locked
    fi
)
cp "${rust_binary_dir}/oldxr-phase7-fastvmess-uring" \
    "${stage_dir}/XrayR-fastengine"

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
    main/geosite.dat \
    fastengine/LICENSE \
    fastengine/NOTICE.md; do
    if [[ ! -f "${repo_root}/${source}" ]]; then
        echo "错误：Release 必需文件不存在：${source}" >&2
        exit 1
    fi
done

cp "${repo_root}/README.md" "${stage_dir}/README.md"
cp "${repo_root}/LICENSE" "${stage_dir}/LICENSE"
cp "${repo_root}/fastengine/LICENSE" "${stage_dir}/FASTENGINE-LICENSE"
cp "${repo_root}/fastengine/NOTICE.md" "${stage_dir}/FASTENGINE-NOTICE.md"
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

chmod +x "${stage_dir}/XrayR" "${stage_dir}/XrayR-fastengine" \
    "${stage_dir}/XrayR-legacy" "${stage_dir}/XrayR.sh"

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
