package dev.lukag.timemygalaxy;

import android.content.Context;
import android.content.SharedPreferences;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

/** Checks the latest GitHub release, cached for a day and silent on failure. */
final class UpdateCheck {

    interface Log {
        void line(String text);
    }

    static final class Latest {
        final String tag;
        final String url;
        final long checkedAt;
        final String error;
        final String apkUrl;
        final String apkSha;
        final String apkName;

        Latest(String tag, String url, long checkedAt, String error) {
            this(tag, url, checkedAt, error, null, null, null);
        }

        Latest(String tag, String url, long checkedAt, String error,
                String apkUrl, String apkSha, String apkName) {
            this.tag = tag;
            this.url = url;
            this.checkedAt = checkedAt;
            this.error = error;
            this.apkUrl = apkUrl;
            this.apkSha = apkSha;
            this.apkName = apkName;
        }
    }

    private static final String API =
            "https://api.github.com/repos/MocLG/Time-My-Galaxy/releases/latest";
    private static final String PREFS = "update";
    private static final long CACHE_MS = 24 * 60 * 60 * 1000L;
    private static final long AUTO_MS = 12 * 60 * 60 * 1000L;
    private static final int MAX_BYTES = 256 * 1024;

    private UpdateCheck() {
    }

    static Latest cached(Context context) {
        SharedPreferences prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        String tag = prefs.getString("tag", null);
        String url = prefs.getString("url", null);
        long at = prefs.getLong("at", 0);
        if (tag == null) {
            return null;
        }
        return new Latest(tag, url, at, null,
                prefs.getString("apk", null),
                prefs.getString("apkSha", null),
                prefs.getString("apkName", null));
    }

    static boolean autoEnabled(Context context) {
        return prefs(context).getBoolean("auto", true);
    }

    static void setAutoEnabled(Context context, boolean enabled) {
        prefs(context).edit().putBoolean("auto", enabled).apply();
    }

    static String offeredTag(Context context) {
        return prefs(context).getString("offered", null);
    }

    static void markOffered(Context context, String tag) {
        prefs(context).edit().putString("offered", tag).apply();
    }

    static void clearOffered(Context context) {
        prefs(context).edit().remove("offered").apply();
    }

    /**
     * One automatic attempt per 12 h, only while a network is available, so an
     * app opened often does not hit GitHub on every launch. A failed attempt
     * still counts, so a blocked network is retried on the next interval.
     */
    static Latest auto(Context context, Log log) {
        Latest cached = cached(context);
        if (!autoEnabled(context) || !online(context)) {
            return cached;
        }
        long now = System.currentTimeMillis();
        if (now - prefs(context).getLong("attempt", 0) < AUTO_MS) {
            return cached;
        }
        prefs(context).edit().putLong("attempt", now).apply();
        return check(context, true, log);
    }

    private static boolean online(Context context) {
        ConnectivityManager manager =
                (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
        if (manager == null) {
            return false;
        }
        Network network = manager.getActiveNetwork();
        if (network == null) {
            return false;
        }
        NetworkCapabilities caps = manager.getNetworkCapabilities(network);
        return caps != null
                && caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET);
    }

    private static SharedPreferences prefs(Context context) {
        return context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    static Latest check(Context context, boolean force, Log log) {
        Latest cached = cached(context);
        if (!force && cached != null && System.currentTimeMillis() - cached.checkedAt < CACHE_MS) {
            return cached;
        }
        try {
            JSONObject json = new JSONObject(fetch());
            String tag = json.optString("tag_name", "");
            String url = json.optString("html_url", BuildConfig.REPO_URL);
            if (tag.isEmpty()) {
                throw new java.io.IOException("release has no tag");
            }
            String apkUrl = null;
            String apkSha = null;
            String apkName = null;
            JSONArray assets = json.optJSONArray("assets");
            for (int i = 0; assets != null && i < assets.length(); i++) {
                JSONObject asset = assets.optJSONObject(i);
                if (asset == null) {
                    continue;
                }
                String name = asset.optString("name", "");
                String download = asset.optString("browser_download_url", "");
                if (!name.toLowerCase(java.util.Locale.ROOT).endsWith(".apk")
                        || download.isEmpty()) {
                    continue;
                }
                apkName = name;
                apkUrl = download;
                String digest = asset.optString("digest", "");
                if (digest.startsWith("sha256:")) {
                    apkSha = digest.substring(7);
                }
                break;
            }
            long now = System.currentTimeMillis();
            context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
                    .putString("tag", tag)
                    .putString("url", url)
                    .putString("apk", apkUrl)
                    .putString("apkSha", apkSha)
                    .putString("apkName", apkName)
                    .putLong("at", now)
                    .apply();
            if (log != null) {
                log.line("[+] latest release " + tag);
            }
            return new Latest(tag, url, now, null, apkUrl, apkSha, apkName);
        } catch (Throwable t) {
            if (log != null && force) {
                log.line("[i] update check unavailable: " + message(t));
            }
            return cached;
        }
    }

    static boolean isNewer(String tag) {
        String[] latest = numbers(tag);
        String[] current = numbers(BuildConfig.VERSION_NAME);
        for (int i = 0; i < Math.max(latest.length, current.length); i++) {
            int a = i < latest.length ? Integer.parseInt(latest[i]) : 0;
            int b = i < current.length ? Integer.parseInt(current[i]) : 0;
            if (a != b) {
                return a > b;
            }
        }
        return false;
    }

    private static String[] numbers(String version) {
        String text = version == null ? "" : version.trim();
        if (text.startsWith("v") || text.startsWith("V")) {
            text = text.substring(1);
        }
        List<String> parts = new ArrayList<>();
        for (String part : text.split("[^0-9]+")) {
            if (!part.isEmpty()) {
                parts.add(part);
            }
        }
        return parts.toArray(new String[0]);
    }

    private static String fetch() throws Exception {
        HttpURLConnection connection = (HttpURLConnection) new URL(API).openConnection();
        try {
            connection.setConnectTimeout(5000);
            connection.setReadTimeout(8000);
            connection.setInstanceFollowRedirects(true);
            connection.setUseCaches(false);
            connection.setRequestProperty("User-Agent", "Time-My-Galaxy");
            connection.setRequestProperty("Accept", "application/vnd.github+json");
            int code = connection.getResponseCode();
            if (code != HttpURLConnection.HTTP_OK) {
                throw new java.io.IOException("HTTP " + code);
            }
            try (InputStream in = connection.getInputStream();
                    ByteArrayOutputStream out = new ByteArrayOutputStream()) {
                byte[] buffer = new byte[16 * 1024];
                int read;
                while ((read = in.read(buffer)) > 0) {
                    if (out.size() + read > MAX_BYTES) {
                        throw new java.io.IOException("response is too large");
                    }
                    out.write(buffer, 0, read);
                }
                return out.toString("UTF-8");
            }
        } finally {
            connection.disconnect();
        }
    }

    private static String message(Throwable t) {
        String text = t.getMessage();
        return text == null || text.isEmpty() ? t.getClass().getSimpleName() : text;
    }
}
