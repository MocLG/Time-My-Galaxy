package dev.lukag.timemygalaxy;

import android.content.Context;

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * Fetches one firmware build's payload from the signed release channel.
 *
 * Only the running build's manifest and bundle are ever requested. A reachable
 * signed manifest always wins: its hashes are compared with the saved copy and
 * the bundle is downloaded only when it differs. When the server cannot be
 * reached, the last downloaded bundle is re-verified and used. Nothing is
 * bundled in the APK, so the first run needs a working connection.
 */
final class PayloadChannel {

    interface Log {
        void line(String text);
    }

    static final class Resolution {
        final Targets.Target target;
        final String note;
        final String error;

        Resolution(Targets.Target target, String note, String error) {
            this.target = target;
            this.note = note;
            this.error = error;
        }

        boolean ok() {
            return target != null;
        }
    }

    static final String BASE =
            "https://github.com/MocLG/Time-My-Galaxy/releases/download/payloads/";

    private static final int MANIFEST_TIMEOUT_MS = 4000;
    private static final int ZIP_CONNECT_TIMEOUT_MS = 8000;
    private static final int ZIP_READ_TIMEOUT_MS = 30000;
    private static final int MAX_MANIFEST_BYTES = 256 * 1024;
    private static final int MAX_SIGNATURE_BYTES = 16 * 1024;
    private static final long MAX_ZIP_BYTES = 64L * 1024 * 1024;
    private static final String MANIFEST = "manifest.json";
    private static final String MANIFEST_SIG = "manifest.json.sig";

    private PayloadChannel() {
    }

    static Resolution resolve(Context context, Log log) {
        String build = DeviceGate.buildId();
        if (!PayloadStore.usableBuild(build)) {
            return new Resolution(null, null, "cannot read this firmware's build id");
        }
        log.line("[*] payload build " + build + "\n");

        File base = new File(context.getFilesDir(), "payloads");
        File cacheDir = new File(base, build);
        Cached cached = readCache(context, cacheDir, build);

        Manifest remote = null;
        String fetchError = null;
        try {
            remote = fetchManifest(context, build);
            log.line("[*] payload server rev " + remote.rev + "\n");
        } catch (Throwable t) {
            fetchError = message(t);
            log.line("[i] payload server unavailable: " + fetchError + "\n");
        }

        if (remote == null) {
            if (cached != null) {
                log.line("[i] using saved payload " + build + " (rev "
                        + cached.manifest.rev + ")\n");
                return new Resolution(target(cached), "saved copy", null);
            }
            return new Resolution(null, null, fetchError);
        }

        if (cached != null && cached.manifest.rev > remote.rev) {
            log.line("[i] saved payload rev " + cached.manifest.rev
                    + " is newer than server rev " + remote.rev + "\n");
            return new Resolution(target(cached), "saved copy", null);
        }

        if (cached != null && cached.hasFiles(remote)) {
            try {
                saveManifest(cacheDir, remote);
            } catch (Throwable ignored) {
            }
            log.line("[+] payload " + build + " is up to date (rev " + remote.rev + ")\n");
            return new Resolution(remote.target(cacheDir), "up to date", null);
        }

        try {
            File dir = install(base, build, remote, log);
            log.line("[+] payload " + build + " downloaded (rev " + remote.rev + ")\n");
            return new Resolution(remote.target(dir), "downloaded", null);
        } catch (Throwable t) {
            String error = message(t);
            log.line("[-] payload download failed: " + error + "\n");
            if (cached != null) {
                log.line("[i] keeping saved payload " + build + " (rev "
                        + cached.manifest.rev + ")\n");
                return new Resolution(target(cached), "saved copy", error);
            }
            return new Resolution(null, null, error);
        }
    }

    private static Targets.Target target(Cached cached) {
        return cached.manifest.target(cached.dir);
    }

    private static Manifest fetchManifest(Context context, String build) throws Exception {
        byte[] raw = download(BASE + build + ".json", MANIFEST_TIMEOUT_MS,
                MAX_MANIFEST_BYTES);
        byte[] signature = download(BASE + build + ".json.sig", MANIFEST_TIMEOUT_MS,
                MAX_SIGNATURE_BYTES);
        return parse(context, raw, signature, build);
    }

    private static Manifest parse(Context context, byte[] raw, byte[] signature,
            String build) throws Exception {
        verify(context, raw, signature);
        JSONObject json = new JSONObject(new String(raw, StandardCharsets.UTF_8));
        if (json.optInt("schema", 0) != 1) {
            throw new IOException("unsupported payload schema");
        }
        String declared = json.optString("build", "");
        if (!build.equals(declared)) {
            throw new IOException("payload manifest is for " + declared);
        }
        String zipName = "payload-" + build + ".zip";
        if (!zipName.equals(json.optString("zip", ""))) {
            throw new IOException("unexpected payload archive name");
        }
        String zipSha = json.optString("sha256", "");
        if (!isSha256(zipSha)) {
            throw new IOException("payload archive hash missing");
        }
        JSONObject files = json.optJSONObject("files");
        if (files == null) {
            throw new IOException("payload file table missing");
        }
        Map<String, String> hashes = new LinkedHashMap<>();
        Iterator<String> keys = files.keys();
        while (keys.hasNext()) {
            String name = keys.next();
            if (!safeName(name)) {
                throw new IOException("bad payload file name: " + name);
            }
            String value = files.optString(name, "");
            if (!isSha256(value)) {
                throw new IOException("bad hash for " + name);
            }
            hashes.put(name, value);
        }
        for (String name : PayloadStore.FILES) {
            if (!hashes.containsKey(name)) {
                throw new IOException("payload is missing " + name);
            }
        }
        return new Manifest(json, raw, signature, build, zipName, zipSha, hashes);
    }

    private static Cached readCache(Context context, File dir, String build) {
        try {
            File rawFile = new File(dir, MANIFEST);
            File sigFile = new File(dir, MANIFEST_SIG);
            if (!rawFile.isFile() || !sigFile.isFile()) {
                return null;
            }
            byte[] raw = readAll(rawFile, MAX_MANIFEST_BYTES);
            byte[] signature = readAll(sigFile, MAX_SIGNATURE_BYTES);
            Manifest manifest = parse(context, raw, signature, build);
            Cached cached = new Cached(dir, manifest);
            return cached.hasFiles(manifest) ? cached : null;
        } catch (Throwable t) {
            return null;
        }
    }

    private static File install(File base, String build, Manifest manifest, Log log)
            throws Exception {
        if (!base.isDirectory() && !base.mkdirs()) {
            throw new IOException("cannot create " + base);
        }
        cleanStale(base, build);
        File zipFile = null;
        File tmp = new File(base, "." + build + ".tmp-" + System.nanoTime());
        File target = new File(base, build);
        try {
            zipFile = File.createTempFile("payload-" + build + "-", ".zip", base);
            log.line("[*] downloading " + manifest.zipName + "\n");
            downloadTo(BASE + manifest.zipName, ZIP_CONNECT_TIMEOUT_MS,
                    ZIP_READ_TIMEOUT_MS, MAX_ZIP_BYTES, zipFile);
            log.line("[*] downloaded " + zipFile.length() + " bytes\n");
            if (!digest(zipFile).equalsIgnoreCase(manifest.zipSha)) {
                throw new IOException("archive hash mismatch");
            }
            if (!tmp.mkdirs()) {
                throw new IOException("cannot create " + tmp);
            }
            unzip(zipFile, tmp, manifest);
            saveManifest(tmp, manifest);
            swap(tmp, target);
            return target;
        } finally {
            deleteTree(tmp);
            if (zipFile != null) {
                zipFile.delete();
            }
        }
    }

    private static void unzip(File zip, File dir, Manifest manifest) throws Exception {
        Set<String> expected = new HashSet<>(manifest.files.keySet());
        Set<String> seen = new HashSet<>();
        byte[] buffer = new byte[64 * 1024];
        try (ZipInputStream in = new ZipInputStream(new FileInputStream(zip))) {
            ZipEntry entry;
            while ((entry = in.getNextEntry()) != null) {
                String name = entry.getName();
                if (entry.isDirectory()) {
                    continue;
                }
                if (!manifest.files.containsKey(name)) {
                    throw new IOException("unexpected archive entry: " + name);
                }
                if (!seen.add(name)) {
                    throw new IOException("duplicate archive entry: " + name);
                }
                File out = new File(dir, name);
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                try (OutputStream os = new FileOutputStream(out)) {
                    int read;
                    while ((read = in.read(buffer)) > 0) {
                        md.update(buffer, 0, read);
                        os.write(buffer, 0, read);
                    }
                }
                if (!hex(md.digest()).equalsIgnoreCase(manifest.files.get(name))) {
                    throw new IOException("hash mismatch for " + name);
                }
                if (!"profile.json".equals(name)) {
                    out.setExecutable(true, false);
                }
            }
        }
        if (!seen.containsAll(expected)) {
            Set<String> missing = new HashSet<>(expected);
            missing.removeAll(seen);
            throw new IOException("archive is missing " + missing);
        }
    }

    /**
     * Replaces the installed bundle in one step. The old directory is moved
     * aside first and restored if the new one cannot be moved into place.
     */
    private static void swap(File tmp, File target) throws IOException {
        File parent = target.getParentFile();
        File old = new File(parent, "." + target.getName() + ".old-" + System.nanoTime());
        deleteTree(old);
        boolean hadOld = target.exists();
        if (hadOld && !target.renameTo(old)) {
            throw new IOException("cannot move the old payload aside");
        }
        if (!tmp.renameTo(target)) {
            if (hadOld) {
                // Best effort: the old bundle stays usable.
                old.renameTo(target);
            }
            throw new IOException("cannot install the payload");
        }
        deleteTree(old);
    }

    private static void saveManifest(File dir, Manifest manifest) throws IOException {
        writeAtomic(new File(dir, MANIFEST), manifest.raw);
        writeAtomic(new File(dir, MANIFEST_SIG), manifest.sig);
    }

    /** Removes leftovers from an install that was interrupted by a crash. */
    private static void cleanStale(File base, String build) {
        File[] children = base.listFiles();
        if (children == null) {
            return;
        }
        for (File child : children) {
            String name = child.getName();
            if (name.startsWith("." + build + ".")
                    || (name.startsWith("payload-" + build + "-") && name.endsWith(".zip"))) {
                deleteTree(child);
            }
        }
    }

    private static void writeAtomic(File file, byte[] data) throws IOException {
        File tmp = new File(file.getParentFile(), "." + file.getName() + ".tmp");
        try (FileOutputStream out = new FileOutputStream(tmp)) {
            out.write(data);
            out.getFD().sync();
        }
        if (file.exists() && !file.delete()) {
            throw new IOException("cannot replace " + file);
        }
        if (!tmp.renameTo(file)) {
            throw new IOException("cannot write " + file);
        }
    }

    private static void verify(Context context, byte[] data, byte[] signature)
            throws Exception {
        X509Certificate cert;
        try (InputStream in = context.getResources().openRawResource(R.raw.payload_signing)) {
            cert = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(in);
        }
        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(cert.getPublicKey());
        verifier.update(data);
        if (!verifier.verify(signature)) {
            throw new IOException("payload manifest signature is invalid");
        }
    }

    private static byte[] download(String url, int timeoutMs, int maxBytes)
            throws IOException {
        HttpURLConnection connection = open(url, timeoutMs, timeoutMs);
        try (InputStream in = connection.getInputStream();
                ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[16 * 1024];
            int read;
            while ((read = in.read(buffer)) > 0) {
                if (out.size() + read > maxBytes) {
                    throw new IOException("response is too large");
                }
                out.write(buffer, 0, read);
            }
            return out.toByteArray();
        } finally {
            connection.disconnect();
        }
    }

    private static void downloadTo(String url, int connectTimeoutMs, int readTimeoutMs,
            long maxBytes, File file) throws IOException {
        HttpURLConnection connection = open(url, connectTimeoutMs, readTimeoutMs);
        try (InputStream in = connection.getInputStream();
                OutputStream out = new FileOutputStream(file)) {
            byte[] buffer = new byte[64 * 1024];
            long total = 0;
            int read;
            while ((read = in.read(buffer)) > 0) {
                total += read;
                if (total > maxBytes) {
                    throw new IOException("payload archive is too large");
                }
                out.write(buffer, 0, read);
            }
        } finally {
            connection.disconnect();
        }
    }

    private static HttpURLConnection open(String url, int connectTimeoutMs,
            int readTimeoutMs) throws IOException {
        HttpURLConnection connection = (HttpURLConnection) new URL(url).openConnection();
        connection.setConnectTimeout(connectTimeoutMs);
        connection.setReadTimeout(readTimeoutMs);
        connection.setInstanceFollowRedirects(true);
        connection.setUseCaches(false);
        connection.setRequestProperty("User-Agent", "Time-My-Galaxy");
        int code = connection.getResponseCode();
        if (code != HttpURLConnection.HTTP_OK) {
            connection.disconnect();
            throw new IOException("HTTP " + code);
        }
        return connection;
    }

    private static byte[] readAll(File file, int maxBytes) throws IOException {
        long length = file.length();
        if (length <= 0 || length > maxBytes) {
            throw new IOException("unexpected file size: " + file);
        }
        try (InputStream in = new FileInputStream(file);
                ByteArrayOutputStream out = new ByteArrayOutputStream((int) length)) {
            byte[] buffer = new byte[16 * 1024];
            int read;
            while ((read = in.read(buffer)) > 0) {
                if (out.size() + read > maxBytes) {
                    throw new IOException("file is too large: " + file);
                }
                out.write(buffer, 0, read);
            }
            return out.toByteArray();
        }
    }

    private static String digest(File file) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        try (InputStream in = new FileInputStream(file)) {
            byte[] buffer = new byte[64 * 1024];
            int read;
            while ((read = in.read(buffer)) > 0) {
                md.update(buffer, 0, read);
            }
        }
        return hex(md.digest());
    }

    private static String hex(byte[] bytes) {
        StringBuilder out = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            out.append(String.format(Locale.US, "%02x", b));
        }
        return out.toString();
    }

    private static boolean isSha256(String value) {
        return value != null && value.matches("[0-9a-fA-F]{64}");
    }

    private static boolean safeName(String name) {
        return name != null && !name.isEmpty()
                && !".".equals(name) && !"..".equals(name)
                && name.matches("[A-Za-z0-9._-]+");
    }

    private static String message(Throwable t) {
        String message = t.getMessage();
        if (message == null || message.isEmpty()) {
            return t.getClass().getSimpleName();
        }
        return message;
    }

    private static void deleteTree(File file) {
        if (file == null || !file.exists()) {
            return;
        }
        File[] children = file.listFiles();
        if (children != null) {
            for (File child : children) {
                deleteTree(child);
            }
        }
        file.delete();
    }

    private static final class Cached {
        final File dir;
        final Manifest manifest;

        Cached(File dir, Manifest manifest) {
            this.dir = dir;
            this.manifest = manifest;
        }

        boolean hasFiles(Manifest wanted) {
            try {
                for (Map.Entry<String, String> entry : wanted.files.entrySet()) {
                    File file = new File(dir, entry.getKey());
                    if (!file.isFile()
                            || !entry.getValue().equalsIgnoreCase(digest(file))) {
                        return false;
                    }
                }
                return true;
            } catch (Exception e) {
                return false;
            }
        }
    }

    private static final class Manifest {
        final JSONObject json;
        final byte[] raw;
        final byte[] sig;
        final String build;
        final String zipName;
        final String zipSha;
        final Map<String, String> files;
        final int rev;

        Manifest(JSONObject json, byte[] raw, byte[] sig, String build, String zipName,
                String zipSha, Map<String, String> files) {
            this.json = json;
            this.raw = raw;
            this.sig = sig;
            this.build = build;
            this.zipName = zipName;
            this.zipSha = zipSha;
            this.files = files;
            this.rev = json.optInt("rev", 0);
        }

        Targets.Target target(File dir) {
            return new Targets.Target(build, meta("model"), meta("soc"), meta("android"),
                    json.optBoolean("verified", false), rev, dir);
        }

        private String meta(String key) {
            String value = json.optString(key, "");
            if (value.isEmpty() || "unknown".equalsIgnoreCase(value)) {
                return null;
            }
            return value;
        }
    }
}
