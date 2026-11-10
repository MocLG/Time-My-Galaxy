# Time-My-Galaxy

CVE-2026-98260 timerfd exploit and Shizuku launcher for Samsung devices.
Payloads are selected per firmware build, keyed by the Samsung PDA string
from `ro.build.version.incremental`.

The exploit runs as the Android shell user (uid 2000) through Shizuku and
loads KernelSU with `me.weishu.kernelsu`. The app never executes a payload
inside its own sandbox.

## Layout

```
Time-My-Galaxy/
├── app/                      Android app (Java sources, manifest, icon)
├── assets/payload/
│   ├── S731BXXU9CZIF/        SM-S731B (S25 FE)
│   └── S731BXXS9CZJ2/        SM-S731B (S25 FE)
├── exploit/
│   ├── build.sh              cross-compiles into assets/payload/
│   └── src/
│       ├── wr_timerfd.c     main chain
│       ├── krw_root.c        kernel read/write helpers
│       ├── cred_swap.c       credential helpers
│       ├── wroot_stage.c     pipe -> workqueue UMH stage
│       └── wr_exec.c         exec shim
├── tools/adb_run.sh          manual ADB fallback for development
├── tools/port_firmware.py    firmware -> offsets/port profile extractor
├── tools/port_firmware.sh    dependency-checking wrapper for the extractor
├── build.sh                  APK build wrapper
└── README.md
```

`app/build.gradle` merges `../assets` into the APK asset tree, so the binaries
exist in exactly one place. `exploit/build.sh` rebuilds them there. Each
`assets/payload/<BUILD>/` directory is one supported firmware build. The
directory name is the build id.

## Build

Most users only need the debug APK:

```sh
./exploit/build.sh      # wr_timerfd + wr_exec -> assets/payload/...
./build.sh              # debug APK (default)
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

To build a signed release APK instead, pass the `release` flag:

```sh
./build.sh release      # signed with ~/.android/release-keystore.properties
./build.sh release /path/to/keystore.properties
adb install -r app/build/outputs/apk/release/app-release.apk
```

Release signing reads `storeFile=`, `alias=`, and `password=` from the given
properties file, then `$KEYSTORE_PROPS`, then
`~/.android/release-keystore.properties`. If none exists, the build fails before
Gradle starts. The keystore and its secrets stay outside the repository. The
debug build does not need a key.

Requires JDK 17, Android SDK platform 35, and
`aarch64-linux-gnu-gcc` for the payload.

## Payloads

| Device | Firmware |
|---|---|
| SM-S731B (S25 FE) | `S731BXXU9CZIF` |
| SM-S731B (S25 FE) | `S731BXXS9CZJ2` |
| SM-S731B (S25 FE) | `S731BXXUACZJC` |

Each `profile.json` is the porter output copied unchanged from
`port-out/<BUILD>/profile.json`. The app trusts only that schema. The porter
sets `verified` with `--verified`, which is used only after the chain completes
on the device.

## Use

1. Start Shizuku as the shell user.
2. Open the app, tap **Grant Shizuku**, then **Stage payloads**.
3. Tap **Plant exploit** and leave the phone alone for 30-60 s.
4. Wait for `done` in the log, then **Check root**.

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
keep LMKD away. Until KernelSU loads, keep the phone idle. **Stop (unsafe)**
requires confirmation and warns that reboot is the only safe cleanup. One plant
per boot. Reboot before retrying.

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
target.java.txt    legacy reference entry (the app discovers assets itself)
System.map         reconstructed kernel symbol table
kernel-config.txt  embedded IKCONFIG
work/              boot.img, Image, vmlinux.elf, vmlinux-to-elf log
```

It reconstructs symbols with `vmlinux-to-elf`, reads BTF for struct sizes and
member offsets, reads IKCONFIG for the VA layout, and finds the allocation
return addresses by decoding the `bl` instructions in `do_timer_create`,
`prepare_ro_creds`, and `dup_task_struct`. Generated values for the reference
build are numerically identical to the verified `S731BXXU9CZIF` constants.

To build a port, create the build directory and compile the exploit:

```sh
mkdir -p assets/payload/<BUILD>
cp assets/payload/S731BXXU9CZIF/wr_exec assets/payload/<BUILD>/
PROFILE=port-out/<BUILD>/offsets.h BUILD=<BUILD> ./exploit/build.sh
cp port-out/<BUILD>/profile.json assets/payload/<BUILD>/profile.json
```

Each build directory also needs a `ksud` late-load helper at
`assets/payload/<BUILD>/ksud`. The bundled S731B `ksud` may work on other
builds. If late-load fails, use a `ksud` built for the target device, kernel,
and KMI.

The directory name is the build id. The APK discovers every
`assets/payload/*` directory that contains a `wr_timerfd` binary at runtime, so
no Java table needs editing. `profile.json` must be the porter-generated file,
copied unchanged from `port-out/<BUILD>/profile.json`. A directory without it
is still usable but is treated as untested.

On start the app compares `Build.FINGERPRINT`, `VERSION.INCREMENTAL`, `DISPLAY`,
and `ID` against the bundled build ids and selects the match (the longest build
id wins). If the matched payload is not marked verified, **Stage payloads** and
**Plant exploit** show a warning and require explicit confirmation. After the
chain completes on the hardware, rerun the porter with `--verified`, copy the
new `profile.json`, and rebuild. Do not hand-edit it.

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
