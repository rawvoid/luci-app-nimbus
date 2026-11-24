#!/bin/sh
# One-click LuCI UI hot-update script for OpenWrt routers.
# Syncs htdocs (JS/assets), menu.d/acl.d JSON, and compiled .lmo translations,
# then clears LuCI caches and reloads rpcd/uhttpd without restarting nimbus.
#
# Usage:
#   ./scripts/deploy-ui.sh                  # Deploy UI to root@10.11.1.1
#   ./scripts/deploy-ui.sh 192.168.1.1      # Deploy UI to another router IP
#   ./scripts/deploy-ui.sh --dry-run        # Stage & list files without SSH

set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH='' cd -- "${SCRIPT_DIR}/.." && pwd)
UI_DIR="${REPO_ROOT}/luci-app-nimbus"

ROUTER_HOST="${ROUTER_HOST:-10.11.1.1}"
ROUTER_USER="${ROUTER_USER:-root}"
ROUTER_PORT="${ROUTER_PORT:-22}"
SSH_IDENTITY="${SSH_IDENTITY:-}"
DO_CHECK=1
DRY_RUN=0

TMP_DIR=""

cleanup() {
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

usage() {
    cat <<'EOF'
Usage: ./scripts/deploy-ui.sh [options] [router_host]

Options:
  -H, --host <ip>        Router IP or hostname (default: 10.11.1.1)
  -u, --user <user>      SSH username (default: root)
  -p, --port <port>      SSH port (default: 22)
  -i, --identity <file>  SSH private key file
      --no-check         Skip local JS/JSON syntax validation
      --dry-run          Build staging bundle and list files without uploading
  -h, --help             Show this help message

Environment overrides:
  ROUTER_HOST, ROUTER_USER, ROUTER_PORT, SSH_IDENTITY
EOF
}

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            -H|--host)
                [ $# -ge 2 ] || die "missing value for $1"
                ROUTER_HOST="$2"
                shift 2
                ;;
            -u|--user)
                [ $# -ge 2 ] || die "missing value for $1"
                ROUTER_USER="$2"
                shift 2
                ;;
            -p|--port)
                [ $# -ge 2 ] || die "missing value for $1"
                ROUTER_PORT="$2"
                shift 2
                ;;
            -i|--identity)
                [ $# -ge 2 ] || die "missing value for $1"
                SSH_IDENTITY="$2"
                shift 2
                ;;
            --no-check)
                DO_CHECK=0
                shift
                ;;
            --dry-run)
                DRY_RUN=1
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            -*)
                die "unknown option: $1"
                ;;
            *)
                ROUTER_HOST="$1"
                shift
                ;;
        esac
    done
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

run_local_checks() {
    if [ "$DO_CHECK" -ne 1 ]; then
        return 0
    fi

    if command -v node >/dev/null 2>&1; then
        printf '[check] validating JS syntax...\n'
        find "${UI_DIR}/htdocs" -type f -name '*.js' | sort | while IFS= read -r f; do
            node --check "$f" || exit 1
        done
    fi

    if command -v jq >/dev/null 2>&1; then
        printf '[check] validating JSON syntax...\n'
        find "${UI_DIR}/root" -type f -name '*.json' | sort | while IFS= read -r f; do
            jq empty "$f" || exit 1
        done
    fi
}

map_luci_lang() {
    case "$1" in
        zh_Hans) printf 'zh-cn' ;;
        zh_Hant) printf 'zh-tw' ;;
        pt_BR)   printf 'pt-br' ;;
        bn_BD)   printf 'bn' ;;
        nb_NO)   printf 'no' ;;
        *)       printf '%s' "$1" ;;
    esac
}

compile_po_python() {
    src_po="$1"
    dst_lmo="$2"
    python3 - "$src_po" "$dst_lmo" <<'PY'
import struct
import sys


def sfh_hash(data: bytes) -> int:
    n = len(data)
    if n <= 0:
        return 0
    h = n & 0xFFFFFFFF
    rem = n & 3
    loops = n >> 2
    idx = 0
    for _ in range(loops):
        h = (h + (data[idx] | (data[idx + 1] << 8))) & 0xFFFFFFFF
        tmp = ((((data[idx + 2] | (data[idx + 3] << 8)) << 11) & 0xFFFFFFFF) ^ h) & 0xFFFFFFFF
        h = (((h << 16) & 0xFFFFFFFF) ^ tmp) & 0xFFFFFFFF
        idx += 4
        h = (h + (h >> 11)) & 0xFFFFFFFF

    def s8(b: int) -> int:
        return b - 256 if b >= 128 else b

    if rem == 3:
        h = (h + (data[idx] | (data[idx + 1] << 8))) & 0xFFFFFFFF
        h = (h ^ ((h << 16) & 0xFFFFFFFF)) & 0xFFFFFFFF
        h = (h ^ ((s8(data[idx + 2]) << 18) & 0xFFFFFFFF)) & 0xFFFFFFFF
        h = (h + (h >> 11)) & 0xFFFFFFFF
    elif rem == 2:
        h = (h + (data[idx] | (data[idx + 1] << 8))) & 0xFFFFFFFF
        h = (h ^ ((h << 11) & 0xFFFFFFFF)) & 0xFFFFFFFF
        h = (h + (h >> 17)) & 0xFFFFFFFF
    elif rem == 1:
        h = (h + s8(data[idx])) & 0xFFFFFFFF
        h = (h ^ ((h << 10) & 0xFFFFFFFF)) & 0xFFFFFFFF
        h = (h + (h >> 1)) & 0xFFFFFFFF

    h = (h ^ ((h << 3) & 0xFFFFFFFF)) & 0xFFFFFFFF
    h = (h + (h >> 5)) & 0xFFFFFFFF
    h = (h ^ ((h << 4) & 0xFFFFFFFF)) & 0xFFFFFFFF
    h = (h + (h >> 17)) & 0xFFFFFFFF
    h = (h ^ ((h << 25) & 0xFFFFFFFF)) & 0xFFFFFFFF
    h = (h + (h >> 6)) & 0xFFFFFFFF
    return h


def extract_string(line: bytes):
    if line.startswith(b'#'):
        return None
    out = bytearray()
    esc = False
    inside = False
    for b in line:
        if not inside:
            if b == 34:
                inside = True
        else:
            if esc:
                if b not in (34, 92):
                    out.append(92)
                out.append(b)
                esc = False
            elif b == 92:
                esc = True
            elif b != 34:
                out.append(b)
            else:
                break
    return bytes(out) if inside else None


def po2lmo(src_path: str, dst_path: str) -> None:
    entries = []
    chunks = bytearray()
    offset = 0

    def pad4(b: bytes) -> bytes:
        rem = (4 - (len(b) % 4)) % 4
        return b + (b'\x00' * rem)

    class Msg:
        def __init__(self):
            self.plural_num = -1
            self.ctxt = None
            self.id = None
            self.id_plural = None
            self.val = [None] * 10
            self.cur_kind = None

    msg = Msg()

    def flush():
        nonlocal offset, msg
        if msg.id is not None and msg.val[0] is not None:
            for i in range(msg.plural_num + 1):
                v = msg.val[i]
                if v is None:
                    continue
                if msg.ctxt is not None and msg.id_plural is not None:
                    key = msg.ctxt + b'\x01' + msg.id + b'\x02' + str(i).encode()
                elif msg.ctxt is not None:
                    key = msg.ctxt + b'\x01' + msg.id
                elif msg.id_plural is not None:
                    key = msg.id + b'\x02' + str(i).encode()
                else:
                    key = msg.id
                key_id = sfh_hash(key)
                val_id = sfh_hash(v)
                if key_id != val_id:
                    entries.append((key_id, msg.plural_num + 1, offset, len(v)))
                    padded = pad4(v)
                    chunks.extend(padded)
                    offset += len(padded)
        elif msg.val[0] is not None:
            raw = msg.val[0]
            parts = raw.split(b'\\n')[:-1] if b'\\n' in raw else []
            for field in parts:
                if field[:14].lower() == b'plural-forms: ':
                    pf = field[14:]
                    entries.append((0, 0, offset, len(pf)))
                    padded = pad4(pf)
                    chunks.extend(padded)
                    offset += len(padded)
                    break
        msg = Msg()

    with open(src_path, 'rb') as f:
        lines = f.readlines()

    for line in lines:
        if line.startswith(b'msgctxt "'):
            if msg.id is not None or msg.val[0] is not None:
                flush()
            else:
                msg.ctxt = None
            msg.cur_kind = ('ctxt', 0)
        elif line.startswith(b'msgid "'):
            if msg.id is not None or msg.val[0] is not None:
                flush()
            else:
                msg.id = None
            msg.cur_kind = ('id', 0)
        elif line.startswith(b'msgid_plural "'):
            msg.id_plural = None
            msg.cur_kind = ('id_plural', 0)
        elif line.startswith(b'msgstr "') or line.startswith(b'msgstr['):
            if line[6:7] == b'[':
                end = line.find(b']', 7)
                msg.plural_num = int(line[7:end])
            else:
                msg.plural_num = 0
            msg.val[msg.plural_num] = None
            msg.cur_kind = ('val', msg.plural_num)

        if msg.cur_kind is not None:
            s = extract_string(line)
            if s:
                kind, idx = msg.cur_kind
                if kind == 'ctxt':
                    msg.ctxt = (msg.ctxt or b'') + s
                elif kind == 'id':
                    msg.id = (msg.id or b'') + s
                elif kind == 'id_plural':
                    msg.id_plural = (msg.id_plural or b'') + s
                elif kind == 'val':
                    msg.val[idx] = (msg.val[idx] or b'') + s

    if msg.id is not None or msg.val[0] is not None:
        flush()

    entries.sort(key=lambda e: e[0])
    if offset > 0:
        with open(dst_path, 'wb') as out:
            out.write(chunks)
            for k, v, off, ln in entries:
                out.write(struct.pack('>4I', k, v, off, ln))
            out.write(struct.pack('>I', offset))


po2lmo(sys.argv[1], sys.argv[2])
PY
}

compile_translations() {
    stage_dir="$1"
    po_root="${UI_DIR}/po"
    [ -d "$po_root" ] || return 0

    i18n_dir="${stage_dir}/usr/lib/lua/luci/i18n"
    mkdir -p "$i18n_dir"

    for lang_dir in "${po_root}"/*; do
        [ -d "$lang_dir" ] || continue
        lang=$(basename "$lang_dir")
        [ "$lang" = "templates" ] && continue
        luci_lang=$(map_luci_lang "$lang")

        for po_file in "${lang_dir}"/*.po; do
            [ -f "$po_file" ] || continue
            base=$(basename "$po_file" .po)
            out_lmo="${i18n_dir}/${base}.${luci_lang}.lmo"
            if command -v po2lmo >/dev/null 2>&1; then
                po2lmo "$po_file" "$out_lmo"
                printf '[i18n] compiled %s -> %s (po2lmo)\n' "$lang/$(basename "$po_file")" "$(basename "$out_lmo")"
            elif command -v python3 >/dev/null 2>&1; then
                compile_po_python "$po_file" "$out_lmo"
                printf '[i18n] compiled %s -> %s (python3)\n' "$lang/$(basename "$po_file")" "$(basename "$out_lmo")"
            else
                printf '[i18n] Warning: neither po2lmo nor python3 found, skipping %s\n' "$po_file" >&2
            fi
        done
    done
}

build_bundle() {
    stage_dir="$1"
    tar_path="$2"
    list_file="${TMP_DIR}/files.list"

    mkdir -p "${stage_dir}/www"
    cp -R "${UI_DIR}/htdocs/"* "${stage_dir}/www/"
    cp -R "${UI_DIR}/root/"* "${stage_dir}/"

    compile_translations "$stage_dir"

    find "$stage_dir" -type d -exec chmod 0755 {} +
    find "$stage_dir" -type f -exec chmod 0644 {} +

    (
        cd "$stage_dir"
        find . -type f | sed 's|^\./||' | sort
    ) > "$list_file"

    [ -s "$list_file" ] || die "staging bundle is empty"

    if tar --version 2>/dev/null | grep -qi 'gnu tar'; then
        COPYFILE_DISABLE=1 tar --format=ustar --owner=0 --group=0 -C "$stage_dir" -T "$list_file" -cf "$tar_path"
    else
        COPYFILE_DISABLE=1 tar --format ustar --uid 0 --gid 0 -C "$stage_dir" -T "$list_file" -cf "$tar_path"
    fi
}

main() {
    parse_args "$@"

    [ -d "${UI_DIR}/htdocs" ] || die "luci-app-nimbus/htdocs not found under ${REPO_ROOT}"
    [ -d "${UI_DIR}/root" ] || die "luci-app-nimbus/root not found under ${REPO_ROOT}"

    require_cmd tar
    if [ "$DRY_RUN" -ne 1 ]; then
        require_cmd ssh
    fi

    run_local_checks

    TMP_DIR=$(mktemp -d)
    STAGE_DIR="${TMP_DIR}/stage"
    BUNDLE_TAR="${TMP_DIR}/nimbus-ui.tar"
    mkdir -p "$STAGE_DIR"

    build_bundle "$STAGE_DIR" "$BUNDLE_TAR"

    printf '[bundle] files to deploy:\n'
    sed 's|^|  /|' "${TMP_DIR}/files.list"

    if [ "$DRY_RUN" -eq 1 ]; then
        printf '[dry-run] bundle verified (%s bytes), skipping SSH upload to %s@%s:%s\n' \
            "$(wc -c < "$BUNDLE_TAR" | tr -d ' ')" "$ROUTER_USER" "$ROUTER_HOST" "$ROUTER_PORT"
        exit 0
    fi

    REMOTE_CMD=$(cat <<'REMOTE_EOF'
set -eu
umask 022
tmp_tar="/tmp/nimbus-ui.$$.tar"
trap 'rm -f "$tmp_tar"' EXIT
cat > "$tmp_tar"
tar -tf "$tmp_tar" >/dev/null
rm -rf /www/luci-static/resources/nimbus /www/luci-static/resources/view/nimbus
mkdir -p /www/luci-static/resources/nimbus /www/luci-static/resources/view/nimbus /usr/share/luci/menu.d /usr/share/rpcd/acl.d /usr/lib/lua/luci/i18n
tar -xf "$tmp_tar" -C /
chown -R 0:0 /www/luci-static/resources/nimbus /www/luci-static/resources/view/nimbus /usr/share/luci/menu.d/luci-app-nimbus.json /usr/share/rpcd/acl.d/luci-app-nimbus.json
for f in /usr/lib/lua/luci/i18n/nimbus.*.lmo; do
    if [ -f "$f" ]; then
        chown 0:0 "$f"
    fi
done
rm -f /tmp/luci-indexcache /tmp/luci-indexcache.*
rm -rf /tmp/luci-modulecache
[ -x /etc/init.d/rpcd ] && /etc/init.d/rpcd reload || true
[ -x /etc/init.d/uhttpd ] && /etc/init.d/uhttpd restart || true
printf "[router] installed views:\n"
ls -1 /www/luci-static/resources/view/nimbus
REMOTE_EOF
)

    printf '[deploy] uploading UI bundle to %s@%s:%s ...\n' "$ROUTER_USER" "$ROUTER_HOST" "$ROUTER_PORT"

    set -- -p "$ROUTER_PORT" -o ConnectTimeout=10
    if [ -n "$SSH_IDENTITY" ]; then
        set -- "$@" -i "$SSH_IDENTITY"
    fi

    # shellcheck disable=SC2029
    ssh "$@" "${ROUTER_USER}@${ROUTER_HOST}" "$REMOTE_CMD" < "$BUNDLE_TAR"

    printf '[done] UI updated on http://%s/cgi-bin/luci/admin/services/nimbus\n' "$ROUTER_HOST"
    printf '       Hard-refresh your browser (Cmd+Shift+R / Ctrl+Shift+R) to load the latest JS & translations.\n'
}

main "$@"
