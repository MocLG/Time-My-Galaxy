#!/usr/bin/env python3
"""Pack and sign the per-build payload bundles for the update channel.

Inputs (all tracked in the repository):

    payloads/<BUILD>/profile.json   porter output for that firmware
    payloads/ksud                   shared KernelSU late-load helper

Built binaries (from exploit/build.sh):

    build/payload/<BUILD>/wr_timerfd
    build/payload/<BUILD>/wr_exec

Outputs, one set per build:

    <out>/<BUILD>.json              signed sha256 table and metadata
    <out>/<BUILD>.json.sig          RSA signature over the exact JSON bytes
    <out>/payload-<BUILD>.zip       wr_timerfd, wr_exec, ksud, profile.json
"""

import argparse
import glob
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
import zipfile

FILES = ("wr_timerfd", "wr_exec", "ksud", "profile.json")
EXECUTABLE = {"wr_timerfd", "wr_exec", "ksud"}
SCHEMA = 1


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sign(key, data, destination):
    with tempfile.NamedTemporaryFile() as payload:
        payload.write(data)
        payload.flush()
        subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", key, "-out", destination, payload.name],
            check=True,
        )


def write_zip(destination, entries):
    # Fixed timestamps and modes keep the archive reproducible for identical
    # inputs, so an unchanged build does not change its hash.
    with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED) as archive:
        for name in FILES:
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            mode = 0o755 if name in EXECUTABLE else 0o644
            info.external_attr = mode << 16
            with open(entries[name], "rb") as handle:
                archive.writestr(info, handle.read())


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", default=os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), help="repository root")
    parser.add_argument("--out", default=None, help="output directory")
    parser.add_argument("--key", required=True, help="PEM private key for signing")
    parser.add_argument("--rev", type=int, default=None,
                        help="monotonic revision (default: git commit count)")
    args = parser.parse_args()

    root = os.path.abspath(args.root)
    out = os.path.abspath(args.out or os.path.join(root, "build", "payloads"))
    key = os.path.abspath(args.key)
    if not os.path.isfile(key):
        sys.exit(f"signing key not found: {key}")

    profiles = sorted(glob.glob(os.path.join(root, "payloads", "*", "profile.json")))
    if not profiles:
        sys.exit("no payloads/*/profile.json found")

    ksud = os.path.join(root, "payloads", "ksud")
    if not os.path.isfile(ksud):
        sys.exit(f"missing shared helper: {ksud}")

    rev = args.rev
    if rev is None:
        rev = int(subprocess.check_output(
            ["git", "rev-list", "--count", "HEAD"], cwd=root, text=True).strip())

    os.makedirs(out, exist_ok=True)
    generated = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    for profile_path in profiles:
        build = os.path.basename(os.path.dirname(profile_path))
        with open(profile_path, "r", encoding="utf-8") as handle:
            profile = json.load(handle)

        source = os.path.join(root, "build", "payload", build)
        entries = {
            "wr_timerfd": os.path.join(source, "wr_timerfd"),
            "wr_exec": os.path.join(source, "wr_exec"),
            "ksud": ksud,
            "profile.json": profile_path,
        }
        for name, path in entries.items():
            if not os.path.isfile(path):
                sys.exit(f"{build}: missing {name} at {path}")

        zip_name = f"payload-{build}.zip"
        zip_path = os.path.join(out, zip_name)
        write_zip(zip_path, entries)

        manifest = {
            "schema": SCHEMA,
            "build": build,
            "model": profile.get("model", "unknown"),
            "soc": profile.get("soc", "unknown"),
            "android": profile.get("android", "unknown"),
            "verified": bool(profile.get("verified", False)),
            "rev": rev,
            "generated": generated,
            "zip": zip_name,
            "sha256": sha256_file(zip_path),
            "files": {name: sha256_file(entries[name]) for name in FILES},
        }
        raw = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
        json_path = os.path.join(out, f"{build}.json")
        with open(json_path, "wb") as handle:
            handle.write(raw)
        sign(key, raw, json_path + ".sig")

        print(f"{build}  rev={rev}  zip={manifest['sha256']}")

    print(f"wrote {len(profiles)} build(s) to {out}")


if __name__ == "__main__":
    main()
