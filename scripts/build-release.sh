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

for tool in "${legacy_go_bin}" "${control_go_bin}" "${cargo_bin}" file readelf zip sha256sum; do
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
host_arch="$(uname -m)"

case "${target_arch}" in
    amd64)
        rust_target="x86_64-unknown-linux-musl"
        if [[ "${host_arch}" == "x86_64" ]]; then
            default_musl_cc="musl-gcc"
        else
            default_musl_cc="x86_64-linux-musl-gcc"
        fi
        musl_cc="${X86_64_MUSL_CC:-${default_musl_cc}}"
        musl_linker="${X86_64_MUSL_LINKER:-${musl_cc}}"
        native_host=0
        [[ "${host_arch}" == "x86_64" ]] && native_host=1
        rust_cc_variable="CC_x86_64_unknown_linux_musl"
        rust_linker_variable="CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER"
        ;;
    arm64)
        rust_target="aarch64-unknown-linux-musl"
        if [[ "${host_arch}" =~ ^(aarch64|arm64)$ ]]; then
            default_musl_cc="musl-gcc"
        else
            default_musl_cc="aarch64-linux-musl-gcc"
        fi
        musl_cc="${AARCH64_MUSL_CC:-${default_musl_cc}}"
        musl_linker="${AARCH64_MUSL_LINKER:-${musl_cc}}"
        native_host=0
        [[ "${host_arch}" =~ ^(aarch64|arm64)$ ]] && native_host=1
        rust_cc_variable="CC_aarch64_unknown_linux_musl"
        rust_linker_variable="CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER"
        ;;
esac
rust_binary_dir="${cargo_target_dir}/${rust_target}/release"
command -v "${musl_cc}" >/dev/null 2>&1 || {
    echo "错误：${target_arch} FastEngine musl 编译器不存在：${musl_cc}" >&2
    exit 1
}
if ((native_host == 0)); then
    command -v "${musl_linker}" >/dev/null 2>&1 || {
        echo "错误：${target_arch} FastEngine musl 链接器不存在：${musl_linker}" >&2
        exit 1
    }
fi

version_value="${release_version#v}"
# Keep the legacy binary's Go symbol metadata so govulncheck can distinguish
# linked packages from module-only dependencies. DWARF remains omitted.
legacy_build_flags=(-trimpath -buildvcs=false -ldflags "-w -buildid= -X main.version=${version_value}")
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
    rust_build_env=(
        "CARGO_TARGET_DIR=${cargo_target_dir}"
        "${rust_cc_variable}=${musl_cc}"
        "RUSTFLAGS=-C target-feature=+crt-static"
    )
    if ((native_host == 0)); then
        rust_build_env+=("${rust_linker_variable}=${musl_linker}")
    fi
    env -u CARGO_ENCODED_RUSTFLAGS "${rust_build_env[@]}" \
        "${cargo_bin}" build --release --locked --target "${rust_target}"
)
cp "${rust_binary_dir}/oldxr-phase7-fastvmess-uring" \
    "${stage_dir}/XrayR-fastengine"

if readelf -l "${stage_dir}/XrayR-fastengine" | grep -q 'INTERP'; then
    echo "错误：FastEngine Release 不应依赖动态 ELF interpreter。" >&2
    exit 1
fi
if readelf -d "${stage_dir}/XrayR-fastengine" 2>/dev/null | grep -q '(NEEDED)'; then
    echo "错误：FastEngine Release 仍包含动态 shared-library 依赖。" >&2
    exit 1
fi
echo "FastEngine ELF：$(file -b "${stage_dir}/XrayR-fastengine")"

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
