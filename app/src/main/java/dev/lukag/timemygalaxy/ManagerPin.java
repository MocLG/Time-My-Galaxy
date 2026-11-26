package dev.lukag.timemygalaxy;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Pins the selected provider's manager before a run. Best effort: failures are
 * logged and the caller continues. /data/adb and modules are untouched.
 *
 * The other provider's manager is removed when it is installed, so the phone
 * only ever carries the manager that matches the selected provider.
 */
final class ManagerPin {

    interface Log {
        void line(String text);
    }

    interface Shell {
        String run(String command, long timeoutMs);
    }

    static final class Result {
        final boolean pinned;
        final boolean swapped;
        final String detail;

        Result(boolean pinned, boolean swapped, String detail) {
            this.pinned = pinned;
            this.swapped = swapped;
            this.detail = detail;
        }
    }

    /** The Next apk is 16,682,167 bytes, so the cap cannot be 16 MiB any more. */
    private static final long MAX_APK_BYTES = 32L * 1024 * 1024;
    private static final int CONNECT_TIMEOUT_MS = 15_000;
    private static final int READ_TIMEOUT_MS = 60_000;

    private static final Pattern DUMP_CODE = Pattern.compile("versionCode=(\\d+)");
    private static final Pattern DUMP_NAME = Pattern.compile("versionName=(\\S+)");
    private static final Pattern LIST_CODE = Pattern.compile("versionCode:(\\d+)");
    private static final Pattern COMPONENT = Pattern.compile("(?m)^(\\S+/\\S+)$");

    private ManagerPin() {
    }

    /** Human-readable install state for the Tools card. */
    static String status(Shell shell, Provider provider) {
        Installed now = read(shell, provider.packageName);
        if (now == null) {
            return provider.label + ": cannot read package state";
        }
        if (!now.present) {
            return provider.label + ": not installed";
        }
        if (now.code < 0) {
            return provider.label + ": installed, version unreadable";
        }
        return provider.label + ": " + now.name + " (" + now.code + ")"
                + (now.code == provider.versionCode
                        ? " · pinned" : " · needs " + provider.versionName);
    }

    static Result ensure(File filesDir, Provider provider, Shell shell, Log log) {
        boolean swapped = false;
        String pkg = provider.packageName;
        String staged = "/data/local/tmp/" + provider.apkName;
        try {
            log.line("[*] manager: checking installed " + provider.label);
            Installed now = read(shell, pkg);
            if (now == null) {
                log.line("[!] manager: cannot read package state; leaving it alone");
                return new Result(false, false, "unknown");
            }
            if (now.present && now.code == provider.versionCode) {
                log.line("[+] manager: " + pkg + " " + now.name
                        + " (" + now.code + ")");
                removeOther(provider, shell, log);
                return new Result(true, false, "present");
            }
            if (!now.present) {
                log.line("[*] manager: not installed");
            } else if (now.code < 0) {
                log.line("[!] manager: installed version is unreadable; leaving it alone");
                return new Result(false, false, "unknown version");
            } else {
                log.line("[!] manager: installed " + now.name + " (" + now.code
                        + "), need " + provider.versionName + " (" + provider.versionCode + ")");
            }

            File apk;
            try {
                apk = cacheApk(filesDir, provider, log);
            } catch (Throwable t) {
                log.line("[!] manager: no usable " + provider.versionName + " apk: "
                        + message(t));
                log.line("[i] manager: continuing with the installed manager");
                return new Result(false, swapped, "apk unavailable");
            }

            if (!stage(apk, provider, shell, staged, log)) {
                log.line("[!] manager: staging failed, continuing");
                return new Result(false, swapped, "staging failed");
            }

            if (now.present) {
                log.line("[*] manager: uninstalling " + pkg);
                String out = shell.run("timeout 60 pm uninstall --user 0 "
                        + pkg + " 2>&1", 70_000L);
                if (out.contains("Success")) {
                    log.line("[+] manager: uninstalled");
                } else {
                    log.line("[!] manager: uninstall said: " + oneLine(out)
                            + " (continuing)");
                }
            }

            log.line("[*] manager: installing " + provider.versionName
                    + " (dexopt can take a few seconds)");
            String install = shell.run("timeout 230 pm install "
                    + quote(staged) + " 2>&1", 240_000L);
            if (!install.contains("Success")) {
                log.line("[!] manager: install said: " + oneLine(install));
                log.line("[i] manager: /data/adb, modules and the allowlist are untouched");
                return new Result(false, swapped, "install failed");
            }

            Installed after = read(shell, pkg);
            if (!isPinned(after, provider)) {
                sleep(1000);
                after = read(shell, pkg);
            }
            if (!isPinned(after, provider)) {
                log.line("[!] manager: installed version is not " + provider.versionCode
                        + ", continuing");
                log.line("[i] manager: /data/adb, modules and the allowlist are untouched");
                return new Result(false, swapped, "verify failed");
            }

            swapped = true;
            log.line("[+] manager: installed " + provider.versionName + " ("
                    + provider.versionCode + ")");
            removeOther(provider, shell, log);
            log.line("[i] manager: /data/adb, modules and the allowlist are untouched");
            launchOnce(shell, log, pkg);
            return new Result(true, true, "swapped");
        } catch (Throwable t) {
            log.line("[!] manager: step failed: " + message(t));
            return new Result(false, swapped, "exception");
        }
    }

    /**
     * Only one manager can be usable at a time: the two packages install the
     * same su path and module tree. Best effort, never fails the pin.
     */
    private static void removeOther(Provider provider, Shell shell, Log log) {
        Provider other = provider.isNext() ? Provider.LEGACY : Provider.NEXT;
        String path = shell.run("pm path " + other.packageName + " 2>/dev/null", 30_000L);
        if (path == null || !path.contains("package:")) {
            return;
        }
        log.line("[*] manager: removing " + other.label + " ("
                + other.packageName + ")");
        String out = shell.run("timeout 60 pm uninstall --user 0 "
                + other.packageName + " 2>&1", 70_000L);
        if (out.contains("Success")) {
            log.line("[+] manager: removed " + other.label);
        } else {
            log.line("[!] manager: could not remove " + other.label + ": "
                    + oneLine(out) + " (continuing)");
        }
    }

    /** Null means the package state cannot be read, so never uninstall. */
    private static Installed read(Shell shell, String pkg) {
        String script = "p=$(pm path " + pkg + " 2>&1); rc=$?; "
                + "if [ -n \"$p\" ] && [ $rc -ne 0 ]; then echo __pm_error; "
                + "elif [ -z \"$p\" ]; then echo __absent; "
                + "else echo __present; "
                + "dumpsys package " + pkg
                + " 2>/dev/null | grep -m2 -E 'versionCode=|versionName='; fi";
        String out = shell.run(script, 40_000L);
        if (isShellError(out) || out.contains("__pm_error")) {
            return null;
        }
        if (out.contains("__absent")) {
            return Installed.absent();
        }
        if (!out.contains("__present")) {
            return null;
        }

        Matcher code = DUMP_CODE.matcher(out);
        Matcher name = DUMP_NAME.matcher(out);
        String label = name.find() ? name.group(1) : "?";
        if (code.find()) {
            try {
                return Installed.present(Long.parseLong(code.group(1)), label);
            } catch (NumberFormatException ignored) {
            }
        }

        String list = shell.run("timeout 20 pm list packages --show-versioncode "
                + pkg + " 2>/dev/null", 25_000L);
        if (!isShellError(list)) {
            Matcher listing = LIST_CODE.matcher(list);
            if (listing.find()) {
                try {
                    return Installed.present(Long.parseLong(listing.group(1)), label);
                } catch (NumberFormatException ignored) {
                }
            }
        }
        return Installed.present(-1, label);
    }

    private static boolean isPinned(Installed value, Provider provider) {
        return value != null && value.present && value.code == provider.versionCode;
    }

    private static File cacheApk(File filesDir, Provider provider, Log log) throws Exception {
        File dir = new File(filesDir, "manager");
        if (!dir.isDirectory() && !dir.mkdirs()) {
            throw new IOException("cannot create " + dir);
        }
        File apk = new File(dir, provider.id + "-" + provider.versionCode + ".apk");
        if (isVerified(apk, provider)) {
            log.line("[i] manager: using cached " + provider.versionName + " apk");
            return apk;
        }
        if (apk.exists() && !apk.delete()) {
            throw new IOException("cannot remove stale " + apk);
        }
        File part = new File(dir, provider.id + "-" + provider.versionCode + ".apk.part");
        if (part.exists() && !part.delete()) {
            throw new IOException("cannot remove stale " + part);
        }

        log.line("[*] manager: downloading " + provider.versionName + " apk ("
                + String.format(java.util.Locale.US, "%.1f", provider.apkBytes / 1048576.0)
                + " MiB)");
        PayloadChannel.downloadTo(provider.apkUrl, CONNECT_TIMEOUT_MS, READ_TIMEOUT_MS,
                MAX_APK_BYTES, part);
        if (part.length() != provider.apkBytes) {
            throw new IOException("size " + part.length() + " != " + provider.apkBytes);
        }
        String digest = PayloadStore.digest(part);
        if (!provider.apkSha256.equalsIgnoreCase(digest)) {
            throw new IOException("sha256 " + digest + " != " + provider.apkSha256);
        }
        if (!part.renameTo(apk)) {
            throw new IOException("cannot rename " + part);
        }
        log.line("[+] manager: apk verified sha256 " + digest);
        return apk;
    }

    private static boolean isVerified(File file, Provider provider) {
        try {
            return file.isFile() && file.length() == provider.apkBytes
                    && provider.apkSha256.equalsIgnoreCase(PayloadStore.digest(file));
        } catch (Exception e) {
            return false;
        }
    }

    private static boolean stage(File apk, Provider provider, Shell shell, String staged,
            Log log) {
        try {
            if (provider.apkSha256.equalsIgnoreCase(remoteDigest(shell, staged))) {
                log.line("[i] manager: apk already staged");
                return true;
            }
            log.line("[*] manager: staging " + staged);
            try (InputStream in = new FileInputStream(apk)) {
                ShizukuBridge.writeFile(staged, "644", in);
            }
            String after = remoteDigest(shell, staged);
            if (!provider.apkSha256.equalsIgnoreCase(after)) {
                log.line("[!] manager: staged apk hash "
                        + (after.isEmpty() ? "unreadable" : after) + " does not match");
                return false;
            }
            return true;
        } catch (Throwable t) {
            log.line("[!] manager: staging failed: " + message(t));
            return false;
        }
    }

    private static String remoteDigest(Shell shell, String staged) {
        String out = shell.run("timeout 30 sha256sum " + quote(staged)
                + " 2>/dev/null", 35_000L);
        for (String token : out.split("\\s+")) {
            if (token.matches("[0-9a-fA-F]{64}")) {
                return token;
            }
        }
        return "";
    }

    private static void launchOnce(Shell shell, Log log, String pkg) {
        log.line("[*] manager: launching once so the kernel learns its uid");
        String component = resolveComponent(shell, pkg);
        boolean started = false;
        if (component != null) {
            String out = shell.run("timeout 25 am start -W -n "
                    + quote(component) + " 2>&1", 30_000L);
            started = out.contains("Status: ok") || out.contains("Complete");
        }
        if (!started) {
            String out = shell.run("timeout 25 monkey -p " + pkg
                    + " -c android.intent.category.LAUNCHER 1 2>&1", 30_000L);
            started = out.contains("Events injected: 1");
        }
        if (!started) {
            log.line("[!] manager: could not open the manager; continuing");
            return;
        }

        sleep(3000);
        log.line("[*] manager: returning to Time My Galaxy");
        if (startSelf(shell)) {
            log.line("[+] manager: returned to Time My Galaxy");
            return;
        }
        shell.run("timeout 10 input keyevent KEYCODE_BACK", 15_000L);
        sleep(500);
        if (startSelf(shell)) {
            log.line("[+] manager: returned to Time My Galaxy");
            return;
        }
        shell.run("timeout 10 input keyevent KEYCODE_HOME", 15_000L);
        log.line("[!] manager: could not foreground the app; continuing");
    }

    private static String resolveComponent(Shell shell, String pkg) {
        String out = shell.run("timeout 20 cmd package resolve-activity --brief "
                + "-a android.intent.action.MAIN "
                + "-c android.intent.category.LAUNCHER " + pkg + " 2>/dev/null",
                25_000L);
        Matcher matcher = COMPONENT.matcher(out);
        String found = null;
        while (matcher.find()) {
            found = matcher.group(1);
        }
        return found;
    }

    private static boolean startSelf(Shell shell) {
        String out = shell.run("timeout 20 am start -W --activity-single-top "
                + "--activity-reorder-to-front "
                + "-n dev.lukag.timemygalaxy/.MainActivity 2>&1", 25_000L);
        return out.contains("Status: ok") || out.contains("Complete");
    }

    private static String quote(String value) {
        return ShizukuBridge.shellQuote(value);
    }

    private static boolean isShellError(String out) {
        return out == null || out.trim().startsWith("error: ");
    }

    private static String oneLine(String value) {
        String text = value == null ? "" : value.trim().replaceAll("\\s+", " ");
        if (text.isEmpty()) {
            return "no output";
        }
        return text.length() <= 200 ? text : text.substring(0, 200) + "...";
    }

    private static String message(Throwable t) {
        String text = t.getMessage();
        return text == null || text.isEmpty() ? t.getClass().getSimpleName() : text;
    }

    private static void sleep(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static final class Installed {
        final boolean present;
        final long code;
        final String name;

        private Installed(boolean present, long code, String name) {
            this.present = present;
            this.code = code;
            this.name = name;
        }

        static Installed absent() {
            return new Installed(false, -1L, "?");
        }

        static Installed present(long code, String name) {
            return new Installed(true, code, name);
        }
    }
}
