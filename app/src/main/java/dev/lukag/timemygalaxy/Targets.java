package dev.lukag.timemygalaxy;

import android.content.res.AssetManager;

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Payload table, discovered from assets/payload/&lt;BUILD&gt;/.
 *
 * The directory name is the build id. profile.json adds model, SoC, Android
 * version and the verified flag. A directory without profile.json is still
 * usable but is treated as untested.
 */
final class Targets {

    static final class Target {
        final String build;
        final String model;
        final String soc;
        final String android;
        final boolean verified;

        Target(String build, String model, String soc, String android, boolean verified) {
            this.build = build;
            this.model = model == null || model.isEmpty() ? "unknown" : model;
            this.soc = soc;
            this.android = android;
            this.verified = verified;
        }

        String label() {
            return model + " / " + build;
        }

        String describe() {
            StringBuilder out = new StringBuilder(model);
            if (soc != null) {
                out.append(", ").append(soc);
            }
            if (android != null) {
                out.append(", Android ").append(android);
            }
            if (!verified) {
                out.append(", untested");
            }
            return out.toString();
        }
    }

    private Targets() {
    }

    /** Every payload directory that contains a wr_timerfd binary. */
    static List<Target> all(AssetManager assets) {
        List<Target> out = new ArrayList<>();
        try {
            String[] dirs = assets.list("payload");
            if (dirs != null) {
                for (String dir : dirs) {
                    Target target = loadOne(assets, dir);
                    if (target != null) {
                        out.add(target);
                    }
                }
            }
        } catch (Exception ignored) {
        }
        out.sort((a, b) -> {
            if (a.verified != b.verified) {
                return a.verified ? -1 : 1;
            }
            return a.build.compareToIgnoreCase(b.build);
        });
        return out;
    }

    private static Target loadOne(AssetManager assets, String build) {
        String base = "payload/" + build;
        try {
            String[] files = assets.list(base);
            if (files == null) {
                return null;
            }
            boolean hasTimer = false;
            for (String file : files) {
                if ("wr_timerfd".equals(file)) {
                    hasTimer = true;
                    break;
                }
            }
            if (!hasTimer) {
                return null;
            }
        } catch (Exception e) {
            return null;
        }

        String model = null;
        String soc = null;
        String android = null;
        boolean verified = false;
        try (InputStream in = assets.open(base + "/profile.json")) {
            JSONObject profile = new JSONObject(readAll(in));
            model = meta(profile, "model");
            soc = meta(profile, "soc");
            android = meta(profile, "android");
            verified = profile.optBoolean("verified", false);
        } catch (Exception ignored) {
        }
        return new Target(build, model, soc, android, verified);
    }

    private static String meta(JSONObject profile, String key) {
        String value = profile.optString(key, "");
        if (value.isEmpty() || "unknown".equalsIgnoreCase(value)) {
            return null;
        }
        return value;
    }

    private static String readAll(InputStream in) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int read;
        while ((read = in.read(buffer)) > 0) {
            out.write(buffer, 0, read);
        }
        return out.toString("UTF-8");
    }

    /**
     * Samsung puts the PDA in the fingerprint tail and in VERSION.INCREMENTAL,
     * so match it against the identity strings in order. The longest build id
     * wins if several payloads match the same string.
     */
    static Target detect(AssetManager assets, String... identity) {
        if (identity == null) {
            return null;
        }
        List<Target> all = all(assets);
        for (String value : identity) {
            if (value == null) {
                continue;
            }
            String upper = value.toUpperCase(Locale.US);
            Target best = null;
            for (Target target : all) {
                String build = target.build.toUpperCase(Locale.US);
                if (!upper.contains(build)) {
                    continue;
                }
                if (best == null || build.length() > best.build.length()) {
                    best = target;
                }
            }
            if (best != null) {
                return best;
            }
        }
        return null;
    }

    static String available(AssetManager assets) {
        List<Target> all = all(assets);
        if (all.isEmpty()) {
            return "(none)";
        }
        StringBuilder out = new StringBuilder();
        for (Target target : all) {
            if (out.length() > 0) {
                out.append(", ");
            }
            out.append(target.build);
            if (!target.verified) {
                out.append(" (untested)");
            }
        }
        return out.toString();
    }
}
