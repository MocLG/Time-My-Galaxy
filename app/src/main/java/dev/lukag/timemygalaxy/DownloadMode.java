package dev.lukag.timemygalaxy;

import android.content.Context;

/**
 * Talks to the DMC vault through {@link D2Vault}, which runs as a separate
 * app_process because the vendor service accepts only uid 1000 under the
 * system_server process name.
 *
 * <p>Reading is harmless. Authorizing flips the single byte the bootloader
 * reads and leaves every other byte of the record alone.
 */
final class DownloadMode {

    private static final String MARKER = "TMGD2 ";

    static final class Status {
        final String state;
        final int lock;
        final int maintenance;
        final int at;
        final int err;
        final String raw;

        Status(String state, int lock, int maintenance, int at, int err, String raw) {
            this.state = state;
            this.lock = lock;
            this.maintenance = maintenance;
            this.at = at;
            this.err = err;
            this.raw = raw == null ? "" : raw;
        }

        /** True when the vault answered with a record. */
        boolean known() {
            return lock >= 0 && maintenance >= 0 && at >= 0;
        }

        boolean authorized() {
            return known() && at == 1;
        }

        /** True when the bootloader would answer Download Mode with D2. */
        boolean gated() {
            return known() && lock == 1 && maintenance == 0 && at == 0;
        }

        String text() {
            switch (state) {
                case "unsupported":
                    return "Not available on this firmware";
                case "no-vault":
                    return "No DMC vault on this firmware";
                case "uid-failed":
                    return "Could not switch to the system uid";
                case "read-failed":
                    return "Could not read the vault" + errorSuffix();
                case "write-failed":
                    return "The vault refused the write" + errorSuffix();
                case "verify-failed":
                    return "The write did not stick";
                case "malformed":
                    return "The vault record has an unknown shape";
                case "bad-mode":
                    return "Internal error";
                case "no-answer":
                    return firstLine(raw);
                default:
                    break;
            }
            if (!known()) {
                return "Unknown (" + state + ")";
            }
            String flags = "lock=" + lock + ", maintenance=" + maintenance
                    + ", at=" + at;
            if (at == 1) {
                return "Allowed · " + flags;
            }
            if (gated()) {
                return "D2 blocked · " + flags;
            }
            if (lock == 0) {
                return "Not gated · " + flags;
            }
            return "Not authorized · " + flags;
        }

        private String errorSuffix() {
            return err < 0 ? "" : " (err " + err + ")";
        }
    }

    private DownloadMode() {
    }

    static Status read(Context context) {
        return run(context, "status", 30_000L);
    }

    static Status authorize(Context context) {
        return run(context, "authorize", 45_000L);
    }

    /**
     * Runs the harness through su. --nice-name makes /proc/<pid>/cmdline read
     * system_server, which is the name VaultKeeper checks, and the harness
     * drops to uid 1000 itself.
     */
    private static Status run(Context context, String mode, long timeoutMs) {
        String apk = context.getApplicationInfo().sourceDir;
        String command = "APP=/system/bin/app_process64; "
                + "[ -x \"$APP\" ] || APP=/system/bin/app_process; "
                + "exec \"$APP\" " + Shell.quote("-Djava.class.path=" + apk)
                + " /system/bin --nice-name=system_server "
                + "dev.lukag.timemygalaxy.D2Vault " + mode + " --uid 1000";
        return parse(Shell.root(command, timeoutMs, null));
    }

    private static Status parse(String output) {
        String text = output == null ? "" : output.trim();
        for (String line : text.split("\\R")) {
            if (!line.startsWith(MARKER)) {
                continue;
            }
            String state = "";
            int lock = -1;
            int maintenance = -1;
            int at = -1;
            int err = -1;
            for (String token : line.substring(MARKER.length()).trim().split("\\s+")) {
                int equals = token.indexOf('=');
                if (equals < 0) {
                    continue;
                }
                String key = token.substring(0, equals);
                String value = token.substring(equals + 1);
                try {
                    if ("state".equals(key)) {
                        state = value;
                    } else if ("lock".equals(key)) {
                        lock = Integer.parseInt(value);
                    } else if ("maintenance".equals(key)) {
                        maintenance = Integer.parseInt(value);
                    } else if ("at".equals(key)) {
                        at = Integer.parseInt(value);
                    } else if ("err".equals(key)) {
                        err = Integer.parseInt(value);
                    }
                } catch (NumberFormatException ignored) {
                    // A value this firmware will not explain stays unknown.
                }
            }
            return new Status(state.isEmpty() ? "no-answer" : state,
                    lock, maintenance, at, err, text);
        }
        return new Status("no-answer", -1, -1, -1, -1, text);
    }

    private static String firstLine(String text) {
        String value = text == null ? "" : text.trim();
        int newline = value.indexOf('\n');
        if (newline >= 0) {
            value = value.substring(0, newline).trim();
        }
        if (value.isEmpty()) {
            return "No answer";
        }
        return value.length() > 160 ? value.substring(0, 160) + "..." : value;
    }
}
