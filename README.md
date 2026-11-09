# Time-My-Galaxy

CVE-2026-98260 timerfd exploit and Shizuku launcher for the Samsung
SM-S731B (S25 FE), firmware `S731BXXU9CZIF` / Android 17.

The exploit runs as the Android shell user (uid 2000) through Shizuku and
loads KernelSU with `me.weishu.kernelsu`. The app never executes a payload
inside its own sandbox.

## Layout

```
Time-My-Galaxy/
├── app/                      Android app (Java sources, manifest, icon)
├── assets/payload/
│   └── S731BXXU9CZIF/        binaries packaged into the APK
│       ├── timer_s25fe       exploit
│       ├── wr_exec           libc-free UMH exec shim
│       └── ksud              KernelSU late-load helper
├── exploit/
│   ├── build.sh              cross-compiles into assets/payload/
│   └── src/
│       ├── timer_s25fe.c     main chain
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
exist in exactly one place. `exploit/build.sh` rebuilds them there.

## Build

```sh
./exploit/build.sh      # timer_s25fe + wr_exec -> assets/payload/...
./build.sh              # debug APK
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

Requires JDK 17, Android SDK platform 35, and
`aarch64-linux-gnu-gcc` for the payload.

Verified payload hashes:

| file | sha256 |
|---|---|
| `timer_s25fe` | `fb6077efdbd95a1519ab879c510769a08ea49d110308e3c957f53f48eb122091` |
| `wr_exec` | `2177609ab47d81d4c1ffca758916893b39f65c52d120efed5c392239852378e6` |
| `ksud` | `5cd19258692d87743a92078b25b40974d07e30a4f7e7dbeb10777ae039db7c7c` |

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

The exploit is launched by the Shizuku shell, but it is detached from it:

- `trap '' 1 13` makes `SIGHUP`/`SIGPIPE` ignored.
- `setsid` puts it in a new session and process group, so signals aimed at
  Shizuku's process group do not reach it.
- stdin is `/dev/null`; stdout/stderr go to
  `/data/local/tmp/wr/run.log`, not to a Shizuku pipe.
- The shell that starts it exits, so it is reparented away from
  `shizuku_server`.
- The app supervises it by polling `pidof` and the two log files, not by
  holding a Shizuku process handle.

A Shizuku restart therefore loses only the live log tailer and the app's
visibility. The exploit keeps running; closing the activity, swiping the app
away, or force-stopping the app does not kill it either. The app never calls
`destroy()` on the exploit, and `onDestroy()` only stops the log tailer.

It is still not unkillable:

- The kernel can still deliver `SIGKILL`; no userspace process can block it.
- Root or another shell process can `kill -9` it.
- LMKD can select it under memory pressure.
- A global kill of uid 2000, a kill of its cgroup, or a reboot ends it. The
  new session protects against process-group signals, not against those.

The exploit parks because exiting would free kernel objects that are still
referenced. Killing a parked process can therefore panic the kernel. There is
no safe way to hand those references back from userspace.

Mitigations in place:

- After `done`, the app uses the newly loaded KernelSU `su` to set the parked
  process's `oom_score_adj` to `-1000`, which keeps LMKD from choosing it.
  That value is not a shield against `SIGKILL`, root, or reboot.
- The app logs the inherited `oom_score_adj` at launch. During the 30-60 s
  race, before KernelSU exists, the process is still subject to LMKD, so keep
  the phone idle and avoid launching heavy apps.
- If Shizuku goes away during the run, the app says supervision is paused
  rather than treating the exploit as dead. It resumes polling if Shizuku
  comes back.
- **Stop (unsafe)** kills the detached process by pid, requires explicit
  confirmation, and warns that reboot is the only safe cleanup.
- One plant per boot. If a run failed, reboot before trying again.

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
The build id is read from the AP/BL/CSC filename; a standalone image needs
`--build`.

Requirements: `python3`, `nm` (binutils), `vmlinux-to-elf` (`pipx install
vmlinux-to-elf`), and `lz4`/`zstd` if the kernel is compressed.

The tool writes `port-out/<BUILD>/`:

```
offsets.h          drop-in replacement for the #define block
profile.json       machine-readable values and derivation notes
report.txt         human-readable summary and warnings
target.java.txt    ready-to-paste Targets.Target entry
System.map         reconstructed kernel symbol table
kernel-config.txt  embedded IKCONFIG
work/              boot.img, Image, vmlinux.elf, vmlinux-to-elf log
```

It reconstructs symbols with `vmlinux-to-elf`, reads BTF for struct sizes and
member offsets, reads IKCONFIG for the VA layout, and finds the allocation
return addresses by decoding the `bl` instructions in `do_timer_create`,
`prepare_ro_creds`, and `dup_task_struct`. Generated values are numerically
identical to the verified `S731BXXU9CZIF` constants.

To build a port:

```sh
mkdir -p assets/payload/<BUILD>
cp assets/payload/S731BXXU9CZIF/{wr_exec,ksud} assets/payload/<BUILD>/
PROFILE=port-out/<BUILD>/offsets.h BUILD=<BUILD> ./exploit/build.sh
```

Then add the `target.java.txt` entry, set `verified=true` only after the chain
completes on the hardware, and build the APK. `MEMSTART_PAGE` is board runtime
data and is not derivable from the firmware; the tool defaults to `0x80000`
(the verified S731B value). Use `--memstart-page` if the target board reports
a different `memstart_addr`. `port-out/` is gitignored.

## Warning

This is a kernel exploit. A failed plant can leave stale timerqueue state and
panic the device. Run it only on a device you own and can recover with a hard
reboot (Power + Volume Down, about 10 s).

## License

GPL-2.0-only, the same license as the Linux kernel. See `LICENSE`.
