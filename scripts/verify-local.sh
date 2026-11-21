#!/bin/sh
# Architecture-adaptive local verification script for luci-app-nimbus.
# Usage: ./scripts/verify-local.sh

set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH='' cd -- "${SCRIPT_DIR}/.." && pwd)

SINGBOX_VERSION="1.14.4"
CACHE_ROOT="${XDG_CACHE_HOME:-$HOME/.cache}/luci-app-nimbus"

TMP_DIR=""
TMP_CONTAINER=""

cleanup() {
    if [ -n "$TMP_CONTAINER" ]; then
        docker rm -f "$TMP_CONTAINER" >/dev/null 2>&1 || true
    fi
    if [ -n "$TMP_DIR" ] && [ -d "$TMP_DIR" ]; then
        rm -rf "$TMP_DIR"
    fi
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

die() {
    printf 'Error: %s\n' "$*" >&2
    exit 1
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

compute_sha256() {
    target="$1"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$target" | awk '{print tolower($1)}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$target" | awk '{print tolower($1)}'
    elif command -v openssl >/dev/null 2>&1; then
        openssl dgst -sha256 "$target" | awk '{print tolower($NF)}'
    else
        die "no SHA256 tool found (need sha256sum, shasum, or openssl)"
    fi
}

detect_arch() {
    host_uname=$(uname -m)
    case "$host_uname" in
        arm64|aarch64)
            ARCH="arm64"
            BASE_IMAGE="openwrt/rootfs:armsr-armv8-openwrt-24.10"
            SINGBOX_ASSET="sing-box-${SINGBOX_VERSION}-linux-arm64-musl.tar.gz"
            SINGBOX_SHA256="b95e25f921dc5e17a4cf13327243d1177642c7e35425bf5372862c477c359f56"
            ;;
        x86_64|amd64)
            ARCH="amd64"
            BASE_IMAGE="openwrt/rootfs:x86-64-openwrt-24.10"
            SINGBOX_ASSET="sing-box-${SINGBOX_VERSION}-linux-amd64-musl.tar.gz"
            SINGBOX_SHA256="8f7c5f0651238850d96a0e488e5473cd77ec1a0098f63942e943f475a12057ca"
            ;;
        *)
            die "unsupported host architecture: ${host_uname} (expected arm64/aarch64 or x86_64/amd64)"
            ;;
    esac
    VERIFY_IMAGE="nimbus-verify-rootfs:${ARCH}"
    BIN_DIR="${CACHE_ROOT}/bin/${ARCH}"
    SINGBOX_BIN_CACHE="${BIN_DIR}/sing-box"
    SINGBOX_META="${BIN_DIR}/.sing-box.meta"
}

ensure_singbox_cache() {
    expected_meta="${SINGBOX_VERSION}:${SINGBOX_SHA256}"
    if [ -x "$SINGBOX_BIN_CACHE" ] && [ -f "$SINGBOX_META" ]; then
        current_meta=$(cat "$SINGBOX_META" 2>/dev/null || true)
        if [ "$current_meta" = "$expected_meta" ]; then
            printf '[cache] using cached sing-box %s (%s): %s\n' "$SINGBOX_VERSION" "$ARCH" "$SINGBOX_BIN_CACHE"
            return 0
        fi
    fi

    require_cmd curl
    require_cmd tar

    mkdir -p "$BIN_DIR"
    dl_url="https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VERSION}/${SINGBOX_ASSET}"
    tgz_path="${TMP_DIR}/${SINGBOX_ASSET}"
    extract_dir="${TMP_DIR}/singbox-extract"

    printf '[cache] downloading %s ...\n' "$dl_url"
    curl -fsSL --retry 3 --connect-timeout 15 --max-time 180 -o "$tgz_path" "$dl_url"

    actual_sha256=$(compute_sha256 "$tgz_path")
    if [ "$actual_sha256" != "$SINGBOX_SHA256" ]; then
        die "SHA256 mismatch for ${SINGBOX_ASSET}: expected ${SINGBOX_SHA256}, got ${actual_sha256}"
    fi
    printf '[cache] verified SHA256: %s\n' "$actual_sha256"

    mkdir -p "$extract_dir"
    tar -xzf "$tgz_path" -C "$extract_dir"
    extracted_bin=$(find "$extract_dir" -type f -name 'sing-box' | head -n 1)
    [ -n "$extracted_bin" ] && [ -f "$extracted_bin" ] || die "sing-box binary not found inside ${SINGBOX_ASSET}"

    tmp_bin="${SINGBOX_BIN_CACHE}.tmp.$$"
    tmp_meta="${SINGBOX_META}.tmp.$$"
    cp "$extracted_bin" "$tmp_bin"
    chmod 0755 "$tmp_bin"
    mv -f "$tmp_bin" "$SINGBOX_BIN_CACHE"
    printf '%s\n' "$expected_meta" > "$tmp_meta"
    mv -f "$tmp_meta" "$SINGBOX_META"

    printf '[cache] installed sing-box to %s\n' "$SINGBOX_BIN_CACHE"
}

ensure_docker_image() {
    if ! docker image inspect "$VERIFY_IMAGE" >/dev/null 2>&1; then
        printf '[cache] preparing Docker image %s from %s ...\n' "$VERIFY_IMAGE" "$BASE_IMAGE"
        if ! docker image inspect "$BASE_IMAGE" >/dev/null 2>&1; then
            docker pull "$BASE_IMAGE"
        fi
        base_platform=$(docker image inspect "$BASE_IMAGE" --format '{{.Os}}/{{.Architecture}}{{if .Variant}}/{{.Variant}}{{end}}')
        TMP_CONTAINER="nimbus-verify-setup-$$"
        docker rm -f "$TMP_CONTAINER" >/dev/null 2>&1 || true
        docker run --name "$TMP_CONTAINER" --platform "$base_platform" "$BASE_IMAGE" \
            sh -c 'mkdir -p /var/lock && opkg update && opkg install ucode-mod-uloop && rm -rf /var/opkg-lists/*'
        docker commit --change 'CMD ["/bin/sh"]' "$TMP_CONTAINER" "$VERIFY_IMAGE" >/dev/null
        docker rm -f "$TMP_CONTAINER" >/dev/null 2>&1 || true
        TMP_CONTAINER=""
        printf '[cache] cached Docker image %s (platform %s)\n' "$VERIFY_IMAGE" "$base_platform"
    else
        printf '[cache] using cached Docker image %s\n' "$VERIFY_IMAGE"
    fi

    VERIFY_PLATFORM=$(docker image inspect "$VERIFY_IMAGE" --format '{{.Os}}/{{.Architecture}}{{if .Variant}}/{{.Variant}}{{end}}')
}

run_host_checks() {
    printf '[host] running shellcheck -s sh ...\n'
    sh_list="${TMP_DIR}/sh_files.txt"
    init_list="${TMP_DIR}/init_files.txt"
    : > "$sh_list"
    : > "$init_list"

    find "$REPO_ROOT" \
        \( -path "$REPO_ROOT/.git" -o -path "$REPO_ROOT/node_modules" \) -prune -o \
        -type f -name '*.sh' -print >> "$sh_list"

    if [ -d "${REPO_ROOT}/nimbus/files/etc/hotplug.d" ]; then
        find "${REPO_ROOT}/nimbus/files/etc/hotplug.d" -type f -print >> "$sh_list"
    fi
    if [ -d "${REPO_ROOT}/nimbus/files/etc/uci-defaults" ]; then
        find "${REPO_ROOT}/nimbus/files/etc/uci-defaults" -type f -print >> "$sh_list"
    fi
    if [ -d "${REPO_ROOT}/nimbus/files/etc/init.d" ]; then
        find "${REPO_ROOT}/nimbus/files/etc/init.d" -type f -print >> "$init_list"
    fi

    sh_count=0
    while IFS= read -r f; do
        [ -n "$f" ] || continue
        shellcheck -s sh "$f"
        sh_count=$((sh_count + 1))
    done < "$sh_list"

    init_count=0
    while IFS= read -r f; do
        [ -n "$f" ] || continue
        shellcheck -s sh -e SC2034,SC1091 "$f"
        init_count=$((init_count + 1))
    done < "$init_list"
    printf '[host] shellcheck passed (%d standard script(s), %d init.d script(s))\n' "$sh_count" "$init_count"

    printf '[host] running JSON validation ...\n'
    json_list="${TMP_DIR}/json_files.txt"
    find "$REPO_ROOT" \
        \( -path "$REPO_ROOT/.git" -o -path "$REPO_ROOT/node_modules" \) -prune -o \
        -type f -name '*.json' -print > "$json_list"

    json_count=0
    if command -v jq >/dev/null 2>&1; then
        json_tool="jq"
    elif command -v python3 >/dev/null 2>&1; then
        json_tool="python3"
    else
        json_tool=""
    fi

    while IFS= read -r f; do
        [ -n "$f" ] || continue
        [ -n "$json_tool" ] || die "JSON files found but neither jq nor python3 is installed"
        if [ "$json_tool" = "jq" ]; then
            jq empty "$f"
        else
            python3 -m json.tool "$f" >/dev/null
        fi
        json_count=$((json_count + 1))
    done < "$json_list"
    printf '[host] JSON validation passed (%d file(s))\n' "$json_count"

    printf '[host] running JS syntax checks ...\n'
    js_list="${TMP_DIR}/js_files.txt"
    : > "$js_list"
    if [ -d "${REPO_ROOT}/luci-app-nimbus" ]; then
        find "${REPO_ROOT}/luci-app-nimbus" -path "*/node_modules" -prune -o -type f -name '*.js' -print > "$js_list"
    fi

    js_count=0
    has_eslint=0
    if command -v eslint >/dev/null 2>&1; then
        has_eslint=1
    fi
    while IFS= read -r f; do
        [ -n "$f" ] || continue
        require_cmd node
        node --check "$f"
        if [ "$has_eslint" -eq 1 ]; then
            eslint "$f"
        fi
        js_count=$((js_count + 1))
    done < "$js_list"
    printf '[host] JS checks passed (%d file(s), eslint=%d)\n' "$js_count" "$has_eslint"
}

run_container_checks() {
    printf '[container] starting offline verification (%s, platform=%s, --cap-add=NET_ADMIN --network none) ...\n' \
        "$VERIFY_IMAGE" "$VERIFY_PLATFORM"

    docker run --rm -i \
        --platform "$VERIFY_PLATFORM" \
        --cap-add=NET_ADMIN \
        --network none \
        -v "${REPO_ROOT}:/work:ro" \
        -v "${SINGBOX_BIN_CACHE}:/usr/local/bin/sing-box:ro" \
        -e SINGBOX_BIN=/usr/local/bin/sing-box \
        -e NFT_BIN=/usr/sbin/nft \
        -e TMPDIR=/tmp \
        -w /tmp \
        "$VERIFY_IMAGE" \
        sh -eu -s <<'CONTAINER_EOF'
printf '[container] sing-box version:\n'
/usr/local/bin/sing-box version

printf '[container] verifying baseline table inet nimbus probes (tproxy_redirect + lockdown) ...\n'
cat << 'EOF' > /tmp/nimbus-probe-tproxy.nft
table inet nimbus
delete table inet nimbus
table inet nimbus {
    set lan_ifaces {
        type ifname
        elements = { "br-lan" }
    }
    set bypass_v4 {
        type ipv4_addr
        flags interval
        auto-merge
    }
    set bypass_v6 {
        type ipv6_addr
        flags interval
        auto-merge
    }
    chain prerouting_tcp {
        type nat hook prerouting priority dstnat + 2; policy accept;
        iifname != @lan_ifaces return
        meta l4proto != tcp return
        meta mark 0xff return
        ct status dnat return
        fib daddr type local return
        ip daddr @bypass_v4 return
        ip6 daddr @bypass_v6 return
        meta nfproto ipv4 meta l4proto tcp counter redirect to :7891
        meta nfproto ipv6 meta l4proto tcp counter redirect to :7891
    }
    chain prerouting_udp {
        type filter hook prerouting priority mangle; policy accept;
        iifname != @lan_ifaces return
        meta l4proto != udp return
        meta mark 0xff return
        fib daddr type local return
        ct mark & 0x30 == 0x10 return
        ip daddr @bypass_v4 ct mark set ct mark | 0x10 return
        ip6 daddr @bypass_v6 ct mark set ct mark | 0x10 return
        meta nfproto ipv4 ct mark set ct mark | 0x20 meta l4proto udp meta mark set 0x1 counter tproxy ip to :7892 accept
        meta nfproto ipv6 ct mark set ct mark | 0x20 meta l4proto udp meta mark set 0x1 counter tproxy ip6 to :7892 accept
    }
}
EOF
nft -c -f /tmp/nimbus-probe-tproxy.nft

cat << 'EOF' > /tmp/nimbus-probe-lockdown.nft
table inet nimbus
delete table inet nimbus
table inet nimbus {
    set lan_ifaces {
        type ifname
        elements = { "br-lan" }
    }
    set bypass_v4 {
        type ipv4_addr
        flags interval
        auto-merge
    }
    set bypass_v6 {
        type ipv6_addr
        flags interval
        auto-merge
    }
    chain forward_lockdown {
        type filter hook forward priority filter - 1; policy accept;
        iifname != @lan_ifaces return
        meta l4proto icmpv6 return
        ip daddr @bypass_v4 return
        ip6 daddr @bypass_v6 return
        counter reject with icmpx type admin-prohibited
    }
}
EOF
nft -c -f /tmp/nimbus-probe-lockdown.nft

nft_fixture_count=0
if [ -d /work/tests/fixtures ]; then
    find /work/tests/fixtures -type f -name '*.nft' > /tmp/nft_fixtures.txt
    while IFS= read -r nft_file; do
        [ -n "$nft_file" ] || continue
        printf '[container] nft -c -f %s\n' "$nft_file"
        nft -c -f "$nft_file"
        nft_fixture_count=$((nft_fixture_count + 1))
    done < /tmp/nft_fixtures.txt
fi
printf '[container] nft checks passed (2 baseline probes, %d fixture(s))\n' "$nft_fixture_count"

NIMBUS_LIB="/work/nimbus/files/usr/share/nimbus"
uc_mod_count=0
uc_script_count=0

if [ -d "$NIMBUS_LIB" ]; then
    for uc_file in "$NIMBUS_LIB"/*.uc; do
        [ -f "$uc_file" ] || continue
        base_name=$(basename "$uc_file" .uc)
        if [ "$base_name" = "supervisor" ]; then
            printf '[container] ucode compile check: %s\n' "$uc_file"
            ucode -S -L "$NIMBUS_LIB" -c -o /dev/null "$uc_file"
            uc_script_count=$((uc_script_count + 1))
        else
            printf '[container] ucode module import check: %s\n' "$base_name"
            ucode -S -L "$NIMBUS_LIB" -e "import * as _m from '${base_name}';"
            uc_mod_count=$((uc_mod_count + 1))
        fi
    done
fi

if [ -d /work/nimbus/files/usr/share/rpcd/ucode ]; then
    for uc_file in /work/nimbus/files/usr/share/rpcd/ucode/*.uc; do
        [ -f "$uc_file" ] || continue
        printf '[container] ucode compile check: %s\n' "$uc_file"
        ucode -S -L "$NIMBUS_LIB" -c -o /dev/null "$uc_file"
        uc_script_count=$((uc_script_count + 1))
    done
fi

if [ -d /work/tests/unit ]; then
    for uc_file in /work/tests/unit/*.uc; do
        [ -f "$uc_file" ] || continue
        printf '[container] ucode compile check: %s\n' "$uc_file"
        ucode -S -L "$NIMBUS_LIB" -c -o /dev/null "$uc_file"
        uc_script_count=$((uc_script_count + 1))
    done
fi

printf '[container] ucode checks passed (%d module(s), %d script(s))\n' "$uc_mod_count" "$uc_script_count"

if [ -f /work/tests/run_tests.sh ]; then
    printf '[container] running /work/tests/run_tests.sh ...\n'
    sh /work/tests/run_tests.sh
else
    printf '[container] /work/tests/run_tests.sh not present yet (skipping)\n'
fi
CONTAINER_EOF
}

check_no_uc_out() {
    uc_out_files=$(find "$REPO_ROOT" -path "$REPO_ROOT/.git" -prune -o -name 'uc.out' -print)
    if [ -n "$uc_out_files" ]; then
        die "unexpected uc.out artifact(s) found in repository: ${uc_out_files}"
    fi
    printf '[host] verified zero uc.out artifacts in repository\n'
}

main() {
    require_cmd docker
    require_cmd shellcheck
    docker info >/dev/null 2>&1 || die "Docker daemon is not running or not accessible"

    TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/nimbus-verify.XXXXXX")
    detect_arch
    printf '[info] detected arch=%s base_image=%s\n' "$ARCH" "$BASE_IMAGE"

    ensure_singbox_cache
    ensure_docker_image
    run_host_checks
    run_container_checks
    check_no_uc_out

    printf '[ok] all local verification checks passed!\n'
}

main "$@"
