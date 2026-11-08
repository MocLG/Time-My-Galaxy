package dev.lukag.timemygalaxy;

import android.content.res.AssetManager;

import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Stages the exploit payload into /data/local/tmp/wr through Shizuku.
 * Everything runs as uid 2000; the app sandbox never executes anything.
 */
final class PayloadStore {

    interface Log {
        void line(String text);
    }

    static final String REMOTE_DIR = "/data/local/tmp/wr";

    private static final Map<String, String> FILES = new LinkedHashMap<>();

    static {
        FILES.put("timer_s25fe", "payload/S731BXXU9CZIF/timer_s25fe");
        FILES.put("wr_exec", "payload/S731BXXU9CZIF/wr_exec");
        FILES.put("ksud", "payload/S731BXXU9CZIF/ksud");
    }

    private PayloadStore() {
    }

    static String remotePath(String name) {
        return REMOTE_DIR + "/" + name;
    }

    static boolean isStaged(AssetManager assets) {
        try {
            for (Map.Entry<String, String> entry : FILES.entrySet()) {
                String remote = remotePath(entry.getKey());
                if (!digest(assets, entry.getValue()).equalsIgnoreCase(remoteDigest(remote))) {
                    return false;
                }
            }
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    static void stageAll(AssetManager assets, Log log) throws Exception {
        ensureRemoteDir();
        for (Map.Entry<String, String> entry : FILES.entrySet()) {
            String name = entry.getKey();
            String asset = entry.getValue();
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
