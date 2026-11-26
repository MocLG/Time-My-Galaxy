# Time-My-Galaxy

CVE-2026-98260 timerfd exploit and Shizuku launcher for Samsung devices.
Payloads are keyed by the Samsung PDA string from
`ro.build.version.incremental`.

The exploit runs as the Android shell user (uid 2000) through Shizuku and
loads the selected provider, KernelSU 3.2.5 (`me.weishu.kernelsu`) or
KernelSU-Next 3.4.2 (`com.rifsxd.ksunext`). It never runs inside the app
sandbox.

Payloads are not bundled in the APK and are not needed to build it. On first
use the app downloads the signed bundle for the running build and keeps it for
offline use. The app needs Android 12 or newer. The green Material 3 interface
has three pages: Exploit, Tools, and History.

## Layout

- `app/` Android app sources and resources
- `payloads/<BUILD>/profile.json` per-build profile
- `payloads/ksud-<release>` KernelSU helper per kernel release
- `payloads/ksud-next-<release>` KernelSU-Next helper per kernel release
- `exploit/` payload sources and build script
- `tools/` firmware porting and packing scripts

## Build

The APK needs JDK 17 and Android SDK platform 35:

```sh
./build.sh
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

Payload binaries are compiled separately and are not part of the APK:

```sh
./exploit/build.sh
```

Compiling payloads also needs `aarch64-linux-gnu-gcc`. A signed release APK
needs a keystore properties file:

```sh
./build.sh release /path/to/keystore.properties
```

## Payloads

Supported builds:

- `S731BXXU9CZIF`
- `S731BXXS9CZJ2`
- `S731BXXS8BZG1`
- `S731BXXUACZJC`
- `S731NKSU9CZIF`
- `S731NKSS9BZH2`
- `A376BXXS6BZJ1`
- `S731U1UES7BZF3`
- `X236BXXS7BZI3`
- `A556EXXUIEZJ1`
- `S721BXXUEEZIF`
- `S721BXXUFEZJ6`
- `S721WVLUEEZIF`

Each build has a porter-generated `payloads/<BUILD>/profile.json`, and its
kernel release needs a `payloads/ksud-<release>` helper. A
`payloads/ksud-next-<release>` helper adds the KernelSU-Next provider to the
same release. The packer keys both helpers by kernel release, so one file
covers every build with the same kernel. The app downloads only
the manifest and bundle for the running build, verifies the signature and file
hashes, and stores them in app-private storage. If the server is unreachable,
the last saved bundle is verified again and used, so the first run needs
internet.

The packer also signs `index.json`, the catalogue shown under **Supported
builds**. The index is not needed to run an exploit. The porter's `verified`
flag is set only after a run succeeds on that firmware.

## Use

1. Start Shizuku as the shell user.
2. Open the app and approve the automatic Shizuku prompt.
3. Tap **Run exploit**. The app stages the signed payload into
   `/data/local/tmp/wr` and plants it. Leave the phone idle for 10-60 s.
4. Wait for `done`. The app then shows **Root checks** (root, ksud, modules,
   manager) and saves the run to **History** (last 30 runs).

One plant per boot. Run is disabled until a real reboot. A soft reboot does not
clear the ledger.

**Copy log** copies the current log.

**Root command** runs `su -c <command>` and shows output on Tools and in the
log. **Run checks** repeats the checks at any time. They are informational and
never gate a run.

**Restart SystemUI** reloads the interface and needs uid 0.

**Soft reboot** runs `ksud soft-reboot`, the same path as KernelSU Manager. The
kernel is not rebooted and root stays loaded.

**Export diagnostics** writes every `/data/local/tmp/wr` log plus the session
log to one uncapped text file and opens the share sheet. It works without root
and adds root-only files when `su` is available.

**Repair manager** pins the manager for the selected provider, either KernelSU
3.2.5 or KernelSU-Next 3.4.2, from a hash-checked APK and leaves `/data/adb`
alone. The pin also runs before an exploit but never blocks it. Switching
provider changes which manager the next run installs, and that run removes the
other one.

**KernelSU-Next** on Tools selects the provider. The choice decides which
`ksud` is staged, which late-load arguments the helper passes, and which
manager is pinned. The switch is available only when the bundle for the
running build carries `ksud-next`.

**Load custom zip** runs a bundle you supply instead of the downloaded one, for
one plant. The zip may contain `wr_timerfd`, `wr_exec`, one of `ksud` /
`ksud-next`, an optional `profile.json`, and optionally `tmg.json` (`{"build":
"...", "flavor": "kernelsu" | "kernelsu-next"}`). It is staged like a normal
payload, checked for structure and file hashes, and deleted after the run.

**Supported builds** lists the signed index, marks verified or untested builds
and the current build, and falls back to the running build offline. Tap a row
to copy its build id.

**Dark mode** and the update check are on Tools. The check runs when the app
opens, at most every 12 hours and only while online, and installs a newer
release through root or Shizuku without an app dialog. The header links the
version, commit, and any newer release.

## Process lifetime

The exploit is detached from Shizuku and survives closing the app, restarting
Shizuku, or force-stopping it. It is still killable by `SIGKILL`, root, LMKD,
or reboot. Because a killed parked run would panic the kernel, after `done`
the app clears `panic_on_oops` and sets `oom_score_adj` to `-1000`. There is no
kill button: reboot is the only safe cleanup, and each boot allows one plant.

A successful plant parks because the fake pipe page it installed must stay
mapped.

## Reporting bugs

If a run fails or the app misbehaves, export diagnostics first. Open
**Tools**, tap **Export diagnostics**, and keep the file it creates. Then open
an issue and state the problem clearly, including the device model, firmware
build, and the diagnostics file.

Attach the exported file to the issue. It contains every log from
`/data/local/tmp/wr` plus the app session log.

## Porting

`tools/port_firmware.py` extracts offsets and metadata from a Samsung firmware
(`.tar.md5`, `boot.img`, `boot.img.lz4`, or raw ARM64 `Image`):

```sh
tools/port_firmware.sh AP_*.tar.md5
```

It needs `python3`, `nm`, `vmlinux-to-elf`, and `lz4`/`zstd`. Output goes to
`port-out/<BUILD>/`, with `offsets.h` for the build and `profile.json` for the
payload directory. Copy `profile.json` into `payloads/<BUILD>/` so the packer
can find the build, then build from the generated header:

```sh
PROFILE=port-out/<BUILD>/offsets.h BUILD=<BUILD> ./exploit/build.sh
```

Use `--verified` only after a run succeeds on that firmware. A build without a
`profile.json` or a matching `ksud` helper is not supported. Get the build id
with `adb shell getprop ro.build.version.incremental`.

`MEMSTART_PAGE` defaults to `0x80000` and is not derivable from firmware. Use
`--memstart-page` if the board reports a different `memstart_addr`.

## Warning

This is a kernel exploit. A failed plant can leave stale timerqueue state and
panic the device. Run it only on a device you own and can recover with a hard
reboot (Power + Volume Down, about 10 s).

## License

GPL-2.0-only, the same license as the Linux kernel. See `LICENSE`.
