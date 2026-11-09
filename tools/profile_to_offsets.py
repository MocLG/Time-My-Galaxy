#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Write an offsets.h header from a porter-generated profile.json.

This lets a payload be rebuilt without the original firmware archive. The
profile.json must come from tools/port_firmware.py and contain schema/values.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from port_firmware import STATIC_DEFINES, write_offsets_header


def main(argv: list[str]) -> int:
    if len(argv) not in (2, 3):
        print(f"usage: {Path(argv[0]).name} profile.json [offsets.h]", file=sys.stderr)
        return 2

    src = Path(argv[1])
    dst = Path(argv[2]) if len(argv) == 3 else src.with_name("offsets.h")

    data = json.loads(src.read_text())
    if data.get("schema", 0) < 1 or "values" not in data:
        print(f"error: {src} is not a porter-generated profile", file=sys.stderr)
        return 1

    values = {}
    for name, text in data["values"].items():
        suffix = STATIC_DEFINES[name][1] if name in STATIC_DEFINES else "ULL"
        values[name] = (int(text, 0), suffix)

    write_offsets_header(dst, data["build"], data["kernel"]["version"], values)
    print(dst)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
