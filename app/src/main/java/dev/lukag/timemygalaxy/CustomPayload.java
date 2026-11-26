package dev.lukag.timemygalaxy;

import android.content.Context;
import android.content.SharedPreferences;
import android.net.Uri;

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * A payload bundle the user supplies, for one plant only.
 *
 * The archive is structure-checked, not trusted: names are whitelisted, sizes
 * are capped, every extracted file is hashed, and the folder is re-verified
 * before it is used, so a truncated or edited copy can never be staged.
 */
final class CustomPayload {

    static final class Loaded {
        final Targets.Target target;
        final Provider provider;

        Loaded(Targets.Target target, Provider provider) {
            this.target = target;
            this.provider = provider;
        }
    }

    private static final String PREFS = "wroot-custom";
    private static final String KEY_DIR = "dir";
    private static final String FLAVOR = "tmg.json";
    private static final String STATE = "custom.json";
    private static final long MAX_ZIP_BYTES = 64L * 1024 * 1024;
    private static final long MAX_FILE_BYTES = 64L * 1024 * 1024;
    private static final long MAX_TOTAL_BYTES = 128L * 1024 * 1024;

    private static final Set<String> ALLOWED = new HashSet<>(Arrays.asList(
            "wr_timerfd", "wr_exec", "ksud", "ksud-next", "profile.json", FLAVOR));

    private CustomPayload() {
    }

    static Loaded load(Context context, Uri uri) throws Exception {
        if (uri == null) {
            throw new IOException("no file selected");
        }
        File base = new File(context.getFilesDir(), "custom");
        if (!base.isDirectory() && !base.mkdirs()) {
            throw new IOException("cannot create " + base);
        }

        long stamp = System.nanoTime();
        File zip = new File(base, ".incoming-" + stamp + ".zip");
        File dir = new File(base, String.valueOf(stamp));
        try {
            copy(context, uri, zip);
            if (!dir.mkdirs()) {
                throw new IOException("cannot create " + dir);
            }
            extract(zip, dir);

            JSONObject flavor = readFlavor(dir);
            Provider provider = provider(dir, flavor);
            for (String name : new String[]{"wr_timerfd", "wr_exec", provider.payloadFile}) {
                if (!new File(dir, name).isFile()) {
                    throw new IOException("archive is missing " + name);
                }
            }

            String build = flavor == null ? DeviceGate.buildId()
                    : flavor.optString("build", DeviceGate.buildId());
            if (!PayloadStore.usableBuild(build)) {
                throw new IOException("cannot tell the firmware build; add build to " + FLAVOR);
            }

            JSONObject state = new JSONObject();
            state.put("schema", 1);
            state.put("build", build);
            state.put("model", flavor == null ? "" : flavor.optString("model", ""));
            state.put("soc", flavor == null ? "" : flavor.optString("soc", ""));
            state.put("android", flavor == null ? "" : flavor.optString("android", ""));
            state.put("flavor", provider.id);
            JSONObject files = new JSONObject();
            String[] extracted = dir.list();
            if (extracted == null) {
                throw new IOException("cannot list " + dir);
            }
            for (String name : extracted) {
                if (ALLOWED.contains(name) && new File(dir, name).isFile()) {
                    files.put(name, PayloadStore.digest(new File(dir, name)));
                }
            }
            state.put("files", files);
            write(new File(dir, STATE), state.toString().getBytes(StandardCharsets.UTF_8));

            SharedPreferences prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
            String previous = prefs.getString(KEY_DIR, null);
            prefs.edit().putString(KEY_DIR, dir.getName()).apply();
            if (previous != null && !previous.equals(dir.getName())) {
                deleteTree(new File(base, previous));
            }

            Targets.Target target = new Targets.Target(build,
                    state.optString("model", ""), state.optString("soc", ""),
                    state.optString("android", ""), false, 0, dir, true,
                    Collections.singleton(provider.id));
            return new Loaded(target, provider);
        } catch (Throwable t) {
            deleteTree(dir);
            throw t instanceof Exception ? (Exception) t : new IOException(t.getMessage());
        } finally {
            zip.delete();
        }
    }

    /** Null when nothing usable is stored; a damaged folder is dropped. */
    static Loaded current(Context context) {
        SharedPreferences prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        String name = prefs.getString(KEY_DIR, null);
        if (name == null || !PayloadStore.usableBuild(name)) {
            return null;
        }
        File dir = new File(new File(context.getFilesDir(), "custom"), name);
        try {
            JSONObject state = new JSONObject(
                    new String(read(new File(dir, STATE)), StandardCharsets.UTF_8));
            if (state.optInt("schema", 0) != 1) {
                throw new IOException("unsupported custom schema");
            }
            JSONObject files = state.optJSONObject("files");
            if (files == null) {
                throw new IOException("custom file table missing");
            }
            for (String key : new String[]{"wr_timerfd", "wr_exec"}) {
                if (!files.has(key)) {
                    throw new IOException("custom bundle is missing " + key);
                }
            }
            java.util.Iterator<String> keys = files.keys();
            while (keys.hasNext()) {
                String key = keys.next();
                File file = new File(dir, key);
                if (!ALLOWED.contains(key) || !file.isFile()
                        || !files.optString(key).equalsIgnoreCase(PayloadStore.digest(file))) {
                    throw new IOException("custom bundle is damaged: " + key);
                }
            }
            Provider provider = Provider.of(state.optString("flavor", Provider.LEGACY_ID));
            if (!files.has(provider.payloadFile)) {
                throw new IOException("custom bundle is missing " + provider.payloadFile);
            }
            String build = state.optString("build", "");
            if (!PayloadStore.usableBuild(build)) {
                throw new IOException("custom bundle has no build");
            }
            Targets.Target target = new Targets.Target(build,
                    state.optString("model", ""), state.optString("soc", ""),
                    state.optString("android", ""), false, 0, dir, true,
                    Collections.singleton(provider.id));
            return new Loaded(target, provider);
        } catch (Throwable t) {
            clear(context);
            return null;
        }
    }

    static void clear(Context context) {
        SharedPreferences prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        String name = prefs.getString(KEY_DIR, null);
        prefs.edit().remove(KEY_DIR).apply();
        File base = new File(context.getFilesDir(), "custom");
        if (name != null && PayloadStore.usableBuild(name)) {
            deleteTree(new File(base, name));
        }
        File[] children = base.listFiles();
        if (children != null) {
            for (File child : children) {
                if (child.getName().startsWith(".incoming-")) {
                    deleteTree(child);
                }
            }
        }
    }

    static String describe(Loaded loaded) {
        return loaded.target.describe() + ", " + loaded.provider.label
                + " " + loaded.provider.versionName;
    }

    private static void copy(Context context, Uri uri, File destination) throws Exception {
        try (InputStream in = context.getContentResolver().openInputStream(uri);
                OutputStream out = new FileOutputStream(destination)) {
            if (in == null) {
                throw new IOException("cannot open the selected file");
            }
            byte[] buffer = new byte[64 * 1024];
            long total = 0;
            int read;
            while ((read = in.read(buffer)) > 0) {
                total += read;
                if (total > MAX_ZIP_BYTES) {
                    throw new IOException("archive is larger than 64 MiB");
                }
                out.write(buffer, 0, read);
            }
        }
    }

    private static void extract(File zip, File dir) throws Exception {
        Set<String> seen = new HashSet<>();
        byte[] buffer = new byte[64 * 1024];
        long total = 0;
        try (ZipInputStream in = new ZipInputStream(new FileInputStream(zip))) {
            ZipEntry entry;
            while ((entry = in.getNextEntry()) != null) {
                if (entry.isDirectory()) {
                    continue;
                }
                String name = entry.getName();
                if (!ALLOWED.contains(name)) {
                    throw new IOException("unexpected archive entry: " + name);
                }
                if (!seen.add(name)) {
                    throw new IOException("duplicate archive entry: " + name);
                }
                File out = new File(dir, name);
                long size = 0;
                try (OutputStream os = new FileOutputStream(out)) {
                    int read;
                    while ((read = in.read(buffer)) > 0) {
                        size += read;
                        total += read;
                        if (size > MAX_FILE_BYTES || total > MAX_TOTAL_BYTES) {
                            throw new IOException("archive expands too far");
                        }
                        os.write(buffer, 0, read);
                    }
                }
                if (!"profile.json".equals(name) && !FLAVOR.equals(name)) {
                    out.setExecutable(true, false);
                }
            }
        }
    }

    private static JSONObject readFlavor(File dir) {
        File file = new File(dir, FLAVOR);
        if (!file.isFile()) {
            return null;
        }
        try {
            return new JSONObject(new String(read(file), StandardCharsets.UTF_8));
        } catch (Throwable t) {
            return null;
        }
    }

    /**
     * The flavor is named by tmg.json when it is there; otherwise the daemon
     * that is present decides it. Both daemons without a name is ambiguous.
     */
    private static Provider provider(File dir, JSONObject flavor) throws IOException {
        boolean legacy = new File(dir, Provider.LEGACY.payloadFile).isFile();
        boolean next = new File(dir, Provider.NEXT.payloadFile).isFile();
        String named = flavor == null ? "" : flavor.optString("flavor", "");

        if (!named.isEmpty()) {
            if (!Provider.LEGACY_ID.equals(named) && !Provider.NEXT_ID.equals(named)) {
                throw new IOException("unknown flavor " + named);
            }
            Provider provider = Provider.of(named);
            if (!new File(dir, provider.payloadFile).isFile()) {
                throw new IOException(named + " needs " + provider.payloadFile);
            }
            return provider;
        }
        if (legacy && next) {
            throw new IOException("archive has both ksud and ksud-next; add flavor to " + FLAVOR);
        }
        if (next) {
            return Provider.NEXT;
        }
        if (legacy) {
            return Provider.LEGACY;
        }
        throw new IOException("archive has no ksud or ksud-next");
    }

    private static byte[] read(File file) throws Exception {
        try (InputStream in = new FileInputStream(file);
                ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[16 * 1024];
            int read;
            while ((read = in.read(buffer)) > 0) {
                out.write(buffer, 0, read);
            }
            return out.toByteArray();
        }
    }

    private static void write(File file, byte[] data) throws Exception {
        try (FileOutputStream out = new FileOutputStream(file)) {
            out.write(data);
            out.getFD().sync();
        }
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
}
