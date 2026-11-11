# Time-My-Galaxy

CVE-2026-98260 timerfd exploit and Shizuku launcher for Samsung devices.
Payloads are selected per firmware build, keyed by the Samsung PDA string
from `ro.build.version.incremental`.

The exploit runs as the Android shell user (uid 2000) through Shizuku and
loads KernelSU with `me.weishu.kernelsu`. The app never executes a payload
inside its own sandbox.

Payloads are not bundled in the APK. On first use the app downloads the
bundle for the running build from a signed channel and keeps it for offline
use.

## Layout

```
Time-My-Galaxy/
├── app/                      Android app (Java sources, manifest, icon)
├── payloads/
│   ├── ksud                  shared KernelSU late-load helper
│   ├── S731BXXU9CZIF/        profile.json for one build
│   ├── S731BXXS9CZJ2/        profile.json for one build
│   └── S731BXXUACZJC/        profile.json for one build
├── exploit/
│   ├── build.sh              cross-compiles into build/payload/
│   └── src/
│       ├── wr_timerfd.c     main chain
│       ├── krw_root.c        kernel read/write helpers
│       ├── cred_swap.c       credential helpers
│       ├── wroot_stage.c     pipe -> workqueue UMH stage
│       └── wr_exec.c         exec shim
├── tools/adb_run.sh          manual ADB fallback for development
├── tools/pack_payloads.py    packs and signs the payload bundles
├── tools/port_firmware.py    firmware -> offsets/port profile extractor
├── tools/port_firmware.sh    dependency-checking wrapper for the extractor
├── build.sh                  APK build wrapper
└── README.md
```

Each `payloads/<BUILD>/` directory is one supported firmware build. The
directory name is the build id.

## Build

Most users only need the debug APK:

```sh
./exploit/build.sh      # wr_timerfd + wr_exec -> build/payload/<BUILD>/
./build.sh              # debug APK (default)
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

To build a signed release APK instead, pass the `release` flag and a keystore
properties file:

```sh
./build.sh release /path/to/keystore.properties
adb install -r app/build/outputs/apk/release/app-release.apk
```

Requires JDK 17, Android SDK platform 35, and
`aarch64-linux-gnu-gcc` for the payload.

## Payloads

Supported builds:

- `S731BXXU9CZIF`
- `S731BXXS9CZJ2`
- `S731BXXUACZJC`

Each supported build has `payloads/<BUILD>/profile.json`, the porter output
copied unchanged from `port-out/<BUILD>/profile.json`. The app trusts only
that schema. The porter sets `verified` with `--verified`, which is used only
after the chain completes on the device. `payloads/ksud` is shared by every
bundle.

The app reads the build id from the device, requests only that build's signed
manifest and bundle, verifies the signature and every file hash, and stores
the result in app-private storage. A reachable server always wins. When the
server cannot be reached, the last saved bundle is verified again and used.
The first run needs a working internet connection.

## Use

1. Start Shizuku as the shell user.
2. Open the app and tap **Grant Shizuku**.
3. Tap **Refetch payload** to check the signed channel again, or go straight
   to **Run exploit**, which refetches, stages the payload into
   `/data/local/tmp/wr`, and plants it. Leave the phone alone for 30-60 s.
4. Wait for `done` in the log, then **Check root**.
5. **Restart SystemUI** only works when `su` returns uid 0. It reloads the
   interface and leaves a parked exploit alone.

The helper stages `ksud` to `/data/local/tmp/.ksud-stage`, bind-mounts it over
`/system/bin/logcat`, and late-loads it. The exploit writes
`/data/local/tmp/wr/wr_load.sh`, which `wr_exec` runs as uid 0 in
`u:r:kernel:s0`.

## Process lifetime and kill risk

The exploit runs detached from Shizuku: `setsid`, ignored `SIGHUP`/`SIGPIPE`,
`/dev/null` stdin, and file-backed stdout/stderr. Restarting Shizuku, closing
the app, or force-stopping it does not kill the process. The app only polls
`pidof` and the logs.

It is still killable by `SIGKILL`, root, LMKD under memory pressure, a uid or
cgroup kill, or reboot. Exit would free kernel objects that are still
referenced, so it parks. Killing a parked process can panic the kernel.

After `done`, the app sets the parked process's `oom_score_adj` to `-1000` to
keep LMKD away. Until KernelSU loads, keep the phone idle. There is no kill
button, reboot is the only safe cleanup. One plant per boot. Reboot before
retrying.

## Porting to another device

`tools/port_firmware.py` extracts the firmware-specific constants from a
Samsung firmware. It accepts a `.tar.md5` (AP, BL, CSC, ...), a `boot.img`, a
`boot.img.lz4`, or a raw ARM64 kernel `Image`, and multiple arguments can be
chained in any order:

```sh
tools/port_firmware.sh ~/s25-firmware/AP_S731BXXU9CZIF_*.tar.md5
tools/port_firmware.sh --build S731BXXU9CZIF boot.img.lz4
tools/port_firmware.sh AP_*.tar.md5 BL_*.tar.md5 boot.img.lz4
```

The AP tar is the useful one: it contains `boot.img.lz4`. BL tars contain only
bootloader images and are skipped automatically, so passing them is harmless.
The build id is read from the AP/BL/CSC filename. A standalone image needs
`--build`. On a Samsung device, get `<BUILD>` with
`adb shell getprop ro.build.version.incremental` (the PDA string).

Requirements: `python3`, `nm` (binutils), `vmlinux-to-elf` (`pipx install
vmlinux-to-elf`), and `lz4`/`zstd` if the kernel is compressed.

The tool writes `port-out/<BUILD>/`:

```
offsets.h          drop-in replacement for the #define block
profile.json       build metadata plus machine-readable values
report.txt         human-readable summary and warnings
target.java.txt    legacy reference entry
System.map         reconstructed kernel symbol table
kernel-config.txt  embedded IKCONFIG
work/              boot.img, Image, vmlinux.elf, vmlinux-to-elf log
```

It reconstructs symbols with `vmlinux-to-elf`, reads BTF for struct sizes and
member offsets, reads IKCONFIG for the VA layout, and finds the allocation
return addresses by decoding the `bl` instructions in `do_timer_create`,
`prepare_ro_creds`, and `dup_task_struct`. Generated values for the reference
build are numerically identical to the verified `S731BXXU9CZIF` constants.

To build a port, create the profile directory and compile the exploit:

```sh
mkdir -p payloads/<BUILD>
cp port-out/<BUILD>/profile.json payloads/<BUILD>/profile.json
PROFILE=port-out/<BUILD>/offsets.h BUILD=<BUILD> ./exploit/build.sh
```

The shared helper at `payloads/ksud` is included in every bundle. If late-load
fails, replace it with a `ksud` built for the target device, kernel, and KMI.

The directory name is the build id. The app reads `VERSION.INCREMENTAL` and
falls back to `DISPLAY`, `FINGERPRINT`, and `ID`, so no Java table needs
editing. `profile.json` must be the porter-generated file, copied unchanged
from `port-out/<BUILD>/profile.json`. A build without it is still usable but
is treated as untested.

`MEMSTART_PAGE` is board runtime
data and is not derivable from the firmware. The tool defaults to `0x80000`
(the reference value used by the verified build). Use `--memstart-page` if the
target board reports a different `memstart_addr`. `port-out/` is gitignored.

## Warning

This is a kernel exploit. A failed plant can leave stale timerqueue state and
panic the device. Run it only on a device you own and can recover with a hard
reboot (Power + Volume Down, about 10 s).

## License

GPL-2.0-only, the same license as the Linux kernel. See `LICENSE`.
