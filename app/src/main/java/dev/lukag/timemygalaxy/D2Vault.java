package dev.lukag.timemygalaxy;

import java.lang.reflect.Method;

/**
 * Reads and, on request, changes the DMC record that decides whether Samsung's
 * bootloader accepts Download Mode.
 *
 * <p>The record is a 32-byte blob in a vaultkeeper trustlet. Its first three
 * bytes are flags: lock-screen credential, maintenance mode, and the
 * AT-command authorization. The bootloader refuses Odin when the bytes read
 * [1, 0, 0].
 *
 * <p>This class is compiled into the APK and run by a plain app_process, which
 * puts the vendor's own VaultKeeperManager on the class path. The service
 * accepts uid 1000 under the process name system_server, so the launcher passes
 * --nice-name=system_server and this harness drops to the system uid before it
 * talks to the vault. Only byte 2 is ever changed, and only after a read that
 * returned a well-formed record.
 *
 * <p>Every run prints one TMGD2 line so the caller does not have to read
 * prose.
 */
public final class D2Vault {

    /** The trustlet namespace that holds the download-mode policy record. */
    private static final String VAULT = "DMC";

    /**
     * The vault slot holding the record. Three type names share the value 1 on
     * the firmwares this was recovered from.
     */
    private static final int SLOT = 1;

    private static final int SIZE = 32;
    private static final int LOCK = 0;
    private static final int MAINTENANCE = 1;
    private static final int AT_COMMAND = 2;

    private static final String MANAGER =
            "com.samsung.android.service.vaultkeeper.VaultKeeperManager";

    private static final int EXIT_OK = 0;
    private static final int EXIT_READ_FAILED = 1;
    private static final int EXIT_UNSUPPORTED = 2;
    private static final int EXIT_WRITE_FAILED = 3;
    private static final int EXIT_VERIFY_FAILED = 4;
    private static final int EXIT_UNAVAILABLE = 5;

    private D2Vault() {
    }

    public static void main(String[] args) {
        String mode = "status";
        int uid = 1000;
        for (int i = 0; i < args.length; i++) {
            if ("--uid".equals(args[i]) && i + 1 < args.length) {
                try {
                    uid = Integer.parseInt(args[++i]);
                } catch (NumberFormatException ignored) {
                    // Keep the default and let adopt() report the real uid.
                }
            } else if (!args[i].startsWith("--")) {
                mode = args[i];
            }
        }

        if (!adopt(uid)) {
            report("uid-failed");
            System.exit(EXIT_UNAVAILABLE);
            return;
        }

        int code;
        try {
            code = run(mode);
        } catch (ClassNotFoundException e) {
            report("unsupported");
            code = EXIT_UNSUPPORTED;
        } catch (Throwable t) {
            report("error note=" + note(t));
            code = EXIT_UNAVAILABLE;
        }
        System.out.flush();
        System.exit(code);
    }

    /**
     * Drops to the uid whose package holds ACCESS_VAULTKEEPER_SERVICE. Root
     * does not get that grant from this vendor, uid 1000 does. The SELinux
     * domain is left as the root manager launched it.
     */
    private static boolean adopt(int uid) {
        if (uid <= 0) {
            return true;
        }
        try {
            Class<?> os = Class.forName("android.system.Os");
            Method getuid = os.getMethod("getuid");
            if (number(getuid.invoke(null)) == uid) {
                return true;
            }
            os.getMethod("setgid", int.class).invoke(null, uid);
            os.getMethod("setuid", int.class).invoke(null, uid);
            return number(getuid.invoke(null)) == uid;
        } catch (Throwable t) {
            return false;
        }
    }

    private static int run(String mode) throws Exception {
        boolean authorize = "authorize".equals(mode);
        boolean clear = "clear".equals(mode);
        if (!authorize && !clear && !"status".equals(mode)) {
            report("bad-mode");
            return EXIT_UNAVAILABLE;
        }
        boolean writing = authorize || clear;
        int want = authorize ? 1 : 0;

        Class<?> manager = Class.forName(MANAGER);
        Object vault = manager.getMethod("getInstance", String.class).invoke(null, VAULT);
        if (vault == null) {
            report("no-vault");
            return EXIT_UNAVAILABLE;
        }

        Method read = manager.getMethod("read", int.class);
        Method errorCode = optional(manager, "getErrorCode");
        byte[] record = (byte[]) read.invoke(vault, SLOT);
        if (record == null) {
            report("read-failed err=" + errorOf(vault, errorCode));
            return EXIT_READ_FAILED;
        }
        if (!wellFormed(record)) {
            report("malformed size=" + record.length);
            return EXIT_UNSUPPORTED;
        }

        int lock = record[LOCK];
        int maintenance = record[MAINTENANCE];
        int at = record[AT_COMMAND];
        int error = errorOf(vault, errorCode);

        if (!writing) {
            report(at == 1 ? "authorized" : "not-authorized",
                    lock, maintenance, at, error);
            return EXIT_OK;
        }
        if (at == want) {
            report(authorize ? "already-authorized" : "already-cleared",
                    lock, maintenance, at, error);
            return EXIT_OK;
        }

        // Only the authorization byte changes. The opaque tail and the other
        // two flags go back exactly as they were read.
        byte[] next = record.clone();
        next[AT_COMMAND] = (byte) want;
        Object result = manager.getMethod("write", int.class, byte[].class)
                .invoke(vault, SLOT, next);
        int code = number(result);
        if (code != 0) {
            report("write-failed", lock, maintenance, at, code);
            return EXIT_WRITE_FAILED;
        }

        byte[] after = (byte[]) read.invoke(vault, SLOT);
        int afterAt = after != null && after.length == SIZE ? after[AT_COMMAND] : -1;
        if (afterAt != want) {
            int afterLock = after != null && after.length > LOCK ? after[LOCK] : lock;
            int afterMaintenance = after != null && after.length > MAINTENANCE
                    ? after[MAINTENANCE] : maintenance;
            report("verify-failed", afterLock, afterMaintenance, afterAt,
                    errorOf(vault, errorCode));
            return EXIT_VERIFY_FAILED;
        }

        report(authorize ? "written" : "cleared",
                after[LOCK], after[MAINTENANCE], afterAt, errorOf(vault, errorCode));
        return EXIT_OK;
    }

    /**
     * True when the record looks like the policy blob this code understands:
     * exactly 32 bytes, with each of the three flags either 0 or 1. A record of
     * another shape is reported and never written.
     */
    private static boolean wellFormed(byte[] record) {
        if (record == null || record.length != SIZE) {
            return false;
        }
        for (int offset = LOCK; offset <= AT_COMMAND; offset++) {
            if (record[offset] != 0 && record[offset] != 1) {
                return false;
            }
        }
        return true;
    }

    private static Method optional(Class<?> type, String name) {
        try {
            return type.getMethod(name);
        } catch (NoSuchMethodException e) {
            return null;
        }
    }

    private static int errorOf(Object vault, Method errorCode) {
        if (errorCode == null) {
            return -1;
        }
        try {
            return number(errorCode.invoke(vault));
        } catch (Throwable t) {
            return -1;
        }
    }

    private static int number(Object value) {
        return value instanceof Number ? ((Number) value).intValue() : Integer.MIN_VALUE;
    }

    private static String note(Throwable t) {
        String message = t.getMessage();
        String text = t.getClass().getSimpleName()
                + (message == null || message.isEmpty() ? "" : ": " + message);
        text = text.replaceAll("\\s+", "_");
        return text.length() > 120 ? text.substring(0, 120) : text;
    }

    private static void report(String state) {
        System.out.println("TMGD2 state=" + state);
    }

    private static void report(String state, int lock, int maintenance, int at, int error) {
        System.out.println("TMGD2 state=" + state
                + " lock=" + lock
                + " maintenance=" + maintenance
                + " at=" + at
                + " err=" + error);
    }
}
