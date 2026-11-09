package dev.lukag.timemygalaxy;

import android.content.res.AssetManager;

import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Stages one build's exploit payload into /data/local/tmp/wr through Shizuku.
 * Everything runs as uid 2000; the app sandbox never executes anything.
 */
final class PayloadStore {

    interface Log {
        void line(String text);
    }

    static final String REMOTE_DIR = "/data/local/tmp/wr";

    private static final String[] FILES = {"timer_s25fe", "wr_exec", "ksud"};

    private PayloadStore() {
    }

    static String remotePath(String name) {
        return REMOTE_DIR + "/" + name;
    }

    static boolean isStaged(AssetManager assets, String build) {
        if (!usableBuild(build)) {
            return false;
        }
        try {
            for (String name : FILES) {
                String asset = assetPath(build, name);
                String remote = remotePath(name);
                if (!digest(assets, asset).equalsIgnoreCase(remoteDigest(remote))) {
                    return false;
                }
            }
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    static void stageAll(AssetManager assets, String build, Log log) throws Exception {
        if (!usableBuild(build)) {
            throw new IOException("bad payload build id: " + build);
        }
        ensureRemoteDir();

        List<String> missing = missing(assets, build);
        if (!missing.isEmpty()) {
            throw new IOException("payload " + build + " is incomplete: missing "
                    + String.join(", ", missing));
        }

        for (String name : FILES) {
            String asset = assetPath(build, name);
            String remote = remotePath(name);
            String localDigest = digest(assets, asset);
            log.line("[*] staging " + remote + " (" + readableSize(assets, asset) + ")");
            try (InputStream in = assets.open(asset)) {
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

    static String assetPath(String build, String name) {
        return "payload/" + build + "/" + name;
    }

    private static List<String> missing(AssetManager assets, String build) {
        List<String> missing = new ArrayList<>();
        Set<String> present = new HashSet<>();
        try {
            String[] files = assets.list("payload/" + build);
            if (files != null) {
                for (String file : files) {
                    present.add(file);
                }
            }
        } catch (IOException ignored) {
        }
        for (String name : FILES) {
            if (!present.contains(name)) {
                missing.add(name);
            }
        }
        return missing;
    }

    private static boolean usableBuild(String build) {
        return build != null && !build.isEmpty()
                && !".".equals(build) && !"..".equals(build)
                && build.matches("[A-Za-z0-9._-]+");
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

    private static String digest(AssetManager assets, String asset) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        try (InputStream in = assets.open(asset)) {
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

    private static String readableSize(AssetManager assets, String asset) {
        try (InputStream in = assets.open(asset)) {
            int size = in.available();
            return size > 0 ? size + " bytes" : "unknown size";
        } catch (IOException e) {
            return "unknown size";
        }
    }
}
