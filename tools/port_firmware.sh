#!/usr/bin/env bash
# Thin wrapper around port_firmware.py. Keeps dependency checks in one place.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)

missing=()
for tool in python3 nm; do
    command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
done
if ! command -v vmlinux-to-elf >/dev/null 2>&1 && [ ! -x "$HOME/.local/bin/vmlinux-to-elf" ]; then
    missing+=("vmlinux-to-elf")
fi
if [ "${#missing[@]}" -ne 0 ]; then
    printf 'missing required tool(s): %s\n' "${missing[*]}" >&2
    echo 'install: binutils, python3, and `pipx install vmlinux-to-elf`' >&2
    exit 1
fi

exec python3 "$SCRIPT_DIR/port_firmware.py" "$@"
