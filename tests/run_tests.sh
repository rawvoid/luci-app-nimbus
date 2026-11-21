#!/bin/sh

set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH='' cd -- "${SCRIPT_DIR}/.." && pwd)
NIMBUS_LIB="${REPO_ROOT}/nimbus/files/usr/share/nimbus"
UNIT_DIR="${SCRIPT_DIR}/unit"

WORK_TMP=$(mktemp -d "${TMPDIR:-/tmp}/nimbus-unit.XXXXXX")

cleanup() {
	if [ -n "$WORK_TMP" ] && [ -d "$WORK_TMP" ]; then
		rm -rf "$WORK_TMP"
	fi
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

export TMPDIR="$WORK_TMP"
export NIMBUS_REPO_ROOT="$REPO_ROOT"

count=0
for test_file in "$UNIT_DIR"/test_*.uc; do
	[ -f "$test_file" ] || continue
	printf '[test] running %s ...\n' "$(basename "$test_file")"
	(
		cd "$WORK_TMP"
		ucode -S -L "$NIMBUS_LIB" "$test_file"
	)
	count=$((count + 1))
done

if [ "$count" -eq 0 ]; then
	printf 'Error: no unit tests found in %s\n' "$UNIT_DIR" >&2
	exit 1
fi

printf '[test] all %d unit test suite(s) passed!\n' "$count"
