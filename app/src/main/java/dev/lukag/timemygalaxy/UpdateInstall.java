package dev.lukag.timemygalaxy;

import android.content.Context;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.MessageDigest;

/**
 * Downloads a release APK and installs it through root or Shizuku.
 *
 * With either privilege the install is silent: the APK is staged under
 * /data/local/tmp and installed with pm install. The system installer is only
 * a fallback for a device where neither is available, and it always shows
 * Android's own confirmation.
 */
final class UpdateInstall {

    interface Log {
        void line(String text);
    }

    private static final int MAX_BYTES = 96 * 1024 * 1024;
    private static final String REMOTE = "/data/local/tmp/tmg-update.apk";

    private UpdateInstall() {
    }

    static File download(Context context, UpdateCheck.Latest latest, Log log)
            throws Exception {
        if (latest.apkUrl == null || latest.apkUrl.isEmpty()) {
            throw new java.io.IOException("release has no apk asset");
        }
        File dir = new File(context.getCacheDir(), "update");
        if (!dir.isDirectory() && !dir.mkdirs()) {
            throw new java.io.IOException("cannot create " + dir);
        }
        File apk = new File(dir, "tmg-update.apk");
        File part = new File(dir, "tmg-update.part");
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        HttpURLConnection connection =
                (HttpURLConnection) new URL(latest.apkUrl).openConnection();
        try {
            connection.setConnectTimeout(10000);
            connection.setReadTimeout(30000);
            connection.setInstanceFollowRedirects(true);
            connection.setUseCaches(false);
            connection.setRequestProperty("User-Agent", "Time-My-Galaxy");
            int code = connection.getResponseCode();
            if (code != HttpURLConnection.HTTP_OK) {
                throw new java.io.IOException("HTTP " + code);
            }
            long total = connection.getContentLengthLong();
            long written = 0;
            try (InputStream in = connection.getInputStream();
                    FileOutputStream sink = new FileOutputStream(part)) {
                byte[] buffer = new byte[32 * 1024];
                int read;
                while ((read = in.read(buffer)) > 0) {
                    written += read;
                    if (written > MAX_BYTES) {
                        throw new java.io.IOException("apk is too large");
                    }
                    digest.update(buffer, 0, read);
                    sink.write(buffer, 0, read);
                }
            }
            if (total > 0 && written != total) {
                throw new java.io.IOException("short download " + written + "/" + total);
            }
            String sha = hex(digest.digest());
            if (latest.apkSha != null && !latest.apkSha.isEmpty()) {
                if (!latest.apkSha.equalsIgnoreCase(sha)) {
                    throw new java.io.IOException("sha256 mismatch");
                }
            } else if (log != null) {
                log.line("[i] release has no sha256; downloaded " + sha);
            }
            if (apk.exists() && !apk.delete()) {
                throw new java.io.IOException("cannot replace " + apk);
            }
            if (!part.renameTo(apk)) {
                throw new java.io.IOException("cannot move the download");
            }
            if (log != null) {
                log.line("[+] downloaded "
                        + (latest.apkName == null ? "update" : latest.apkName)
                        + " (" + apk.length() + " B)");
            }
            return apk;
        } finally {
            connection.disconnect();
            if (part.exists()) {
                part.delete();
            }
        }
    }

    /**
     * Installs silently as root, or as the Shizuku shell user. Returns false
     * when neither can install, so the caller can use the system installer.
     */
    static boolean install(File apk, Log log) {
        if (!ShizukuBridge.isRunning() || !ShizukuBridge.isGranted()) {
            if (log != null) {
                log.line("[i] Shizuku is not granted; using the system installer");
            }
            return false;
        }
        try (InputStream source = new FileInputStream(apk)) {
            ShizukuBridge.writeFile(REMOTE, "644", source);
        } catch (Throwable t) {
            if (log != null) {
                log.line("[!] cannot stage the update: " + t.getMessage());
            }
            return false;
        }
        try {
            boolean root = isRoot();
            String out = root
                    ? Shell.root("pm install -r " + Shell.quote(REMOTE),
                            180000L, null)
                    : Shell.run("pm install -r " + Shell.quote(REMOTE),
                            180000L, null);
            if (log != null) {
                for (String line : out.split("\n")) {
                    String text = line.trim();
                    if (!text.isEmpty()) {
                        log.line("[i] " + text);
                    }
                }
            }
            return out.contains("Success");
        } finally {
            Shell.run("rm -f " + Shell.quote(REMOTE), 5000L, null);
        }
    }

    private static boolean isRoot() {
        String out = Shell.root("id", 5000L, null);
        return out != null && out.contains("uid=0");
    }

    private static String hex(byte[] bytes) {
        StringBuilder out = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            out.append(String.format(java.util.Locale.ROOT, "%02x", b));
        }
        return out.toString();
    }
}
