package dev.lukag.timemygalaxy;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Stages one build's exploit payload into /data/local/tmp/wr through Shizuku.
 * Everything runs as uid 2000; the app sandbox never executes anything.
 *
 * The source directory is the verified bundle in the app's files directory,
 * populated by PayloadChannel. Nothing is bundled in the APK.
 */
final class PayloadStore {

    interface Log {
        void line(String text);
    }

    static final String REMOTE_DIR = "/data/local/tmp/wr";

    static final String[] FILES = {"wr_timerfd", "wr_exec", "ksud"};

    private PayloadStore() {
    }

    static String remotePath(String name) {
        return REMOTE_DIR + "/" + name;
    }

    static boolean isStaged(File dir, String build) {
        if (!usableBuild(build) || dir == null) {
            return false;
        }
        try {
            for (String name : FILES) {
                File local = new File(dir, name);
                if (!local.isFile()) {
                    return false;
                }
                if (!digest(local).equalsIgnoreCase(remoteDigest(remotePath(name)))) {
                    return false;
                }
            }
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    static void stageAll(File dir, String build, Log log) throws Exception {
        if (!usableBuild(build) || dir == null) {
            throw new IOException("bad payload build id: " + build);
        }
        ensureRemoteDir();

        List<String> missing = missing(dir);
        if (!missing.isEmpty()) {
            throw new IOException("payload " + build + " is incomplete: missing "
                    + String.join(", ", missing));
        }

        for (String name : FILES) {
            File local = new File(dir, name);
            String remote = remotePath(name);
            String localDigest = digest(local);
            log.line("[*] staging " + remote + " (" + local.length() + " bytes)");
            try (InputStream in = new FileInputStream(local)) {
                ShizukuBridge.writeFile(remote, "755", in);
            }
            String remoteDigest = remoteDigest(remote);
            if (!localDigest.equalsIgnoreCase(remoteDigest)) {
                throw new IOException("hash mismatch for " + remote
                        + " (local " + localDigest + ", remote " + remoteDigest + ")");
            }
            log.line("[+] " + remote + " sha256=" + localDigest);
        }
    }

    static boolean usableBuild(String build) {
        return build != null && !build.isEmpty()
                && !".".equals(build) && !"..".equals(build)
                && build.matches("[A-Za-z0-9._-]+");
    }

    private static List<String> missing(File dir) {
        List<String> missing = new ArrayList<>();
        for (String name : FILES) {
            if (!new File(dir, name).isFile()) {
                missing.add(name);
            }
        }
        return missing;
    }

    private static void ensureRemoteDir() throws Exception {
        String out = ShizukuBridge.capture(new String[]{"/system/bin/sh", "-c",
                        "mkdir -p " + ShizukuBridge.shellQuote(REMOTE_DIR) + " && echo ok"},
                null, "/data/local/tmp").trim();
        if (!out.contains("ok")) {
            throw new IOException("cannot create " + REMOTE_DIR
                    + (out.isEmpty() ? "" : ": " + out));
        }
    }

    private static String remoteDigest(String remote) throws Exception {
        String out = ShizukuBridge.capture(new String[]{"/system/bin/sh", "-c",
                        "sha256sum " + ShizukuBridge.shellQuote(remote)}, null, REMOTE_DIR).trim();
        String[] parts = out.split("\\s+");
        if (parts.length == 0 || !parts[0].matches("[0-9a-fA-F]{64}")) {
            throw new IOException("sha256sum produced no usable output for " + remote
                    + (out.isEmpty() ? " (empty)" : " (" + out + ")"));
        }
        return parts[0];
    }

    static String digest(File file) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        try (InputStream in = new FileInputStream(file)) {
            byte[] buffer = new byte[64 * 1024];
            int read;
            while ((read = in.read(buffer)) > 0) {
                md.update(buffer, 0, read);
            }
        }
        StringBuilder hex = new StringBuilder();
        for (byte b : md.digest()) {
            hex.append(String.format(Locale.US, "%02x", b));
        }
        return hex.toString();
    }
}
