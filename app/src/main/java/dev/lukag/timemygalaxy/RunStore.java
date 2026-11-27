package dev.lukag.timemygalaxy;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.SystemClock;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;

/**
 * Boot ledger and run history. The ledger keeps one plant per boot: a real
 * reboot changes the kernel boot id, a soft reboot does not.
 */
final class RunStore {

    private static final String LEDGER = "run-ledger";
    private static final String KEY_BOOT_ID = "boot_id";
    private static final String KEY_BOOT_EPOCH = "boot_epoch";
    private static final String KEY_BUILD = "plant_build";
    private static final String KEY_PLANT_AT = "plant_at";
    private static final String HISTORY = "runs.jsonl";
    private static final int MAX_RUNS = 30;
    private static final long BOOT_WINDOW_MS = 120_000L;
    private static final Object LOCK = new Object();

    static final class Begin {
        final String id;
        final String build;
        final long startedAt;
        final boolean verified;
        final int rev;
        final boolean custom;

        Begin(String id, String build, long startedAt, boolean verified, int rev,
                boolean custom) {
            this.id = id;
            this.build = build;
            this.startedAt = startedAt;
            this.verified = verified;
            this.rev = rev;
            this.custom = custom;
        }
    }

    static final class RunRecord {
        final String id;
        final String build;
        final String outcome;
        final String detail;
        final int rev;
        final long startedAt;
        final long finishedAt;
        final long durationMs;
        final boolean verified;
        final boolean root;
        final boolean swapped;
        final boolean custom;

        RunRecord(String id, String build, String outcome, String detail, int rev,
                long startedAt, long finishedAt, long durationMs, boolean verified,
                boolean root, boolean swapped, boolean custom) {
            this.id = id;
            this.build = build;
            this.outcome = outcome;
            this.detail = detail;
            this.rev = rev;
            this.startedAt = startedAt;
            this.finishedAt = finishedAt;
            this.durationMs = durationMs;
            this.verified = verified;
            this.root = root;
            this.swapped = swapped;
            this.custom = custom;
        }

        JSONObject toJson() {
            JSONObject json = new JSONObject();
            try {
                json.put("id", id);
                json.put("build", build);
                json.put("outcome", outcome);
                json.put("detail", detail == null ? "" : detail);
                json.put("rev", rev);
                json.put("startedAt", startedAt);
                json.put("finishedAt", finishedAt);
                json.put("durationMs", durationMs);
                json.put("verified", verified);
                json.put("root", root);
                json.put("swapped", swapped);
                json.put("custom", custom);
            } catch (Throwable ignored) {
            }
            return json;
        }

        static RunRecord from(JSONObject json) {
            return new RunRecord(
                    json.optString("id", ""),
                    json.optString("build", ""),
                    json.optString("outcome", "unknown"),
                    json.optString("detail", ""),
                    json.optInt("rev", 0),
                    json.optLong("startedAt", 0),
                    json.optLong("finishedAt", 0),
                    json.optLong("durationMs", 0),
                    json.optBoolean("verified", false),
                    json.optBoolean("root", false),
                    json.optBoolean("swapped", false),
                    json.optBoolean("custom", false));
        }

        String meta() {
            return meta(null);
        }

        String meta(Context context) {
            StringBuilder out = new StringBuilder();
            out.append(durationMs > 0 ? (durationMs / 1000) + "s" : "—");
            if (rev > 0) {
                out.append(" · rev ").append(rev);
            }
            if (context != null) {
                out.append(" · ").append(context.getString(root ? R.string.run_root_ok : R.string.run_no_root));
                if (swapped) {
                    out.append(" · ").append(context.getString(R.string.run_manager_swapped));
                }
                if (custom) {
                    out.append(" · ").append(context.getString(R.string.custom));
                }
            } else {
                out.append(" · ").append(root ? "root ok" : "no root");
                if (swapped) {
                    out.append(" · manager swapped");
                }
                if (custom) {
                    out.append(" · custom");
                }
            }
            return out.toString();
        }
    }

    private RunStore() {
    }

    static String blockReason(Context context) {
        SharedPreferences prefs = context.getSharedPreferences(LEDGER, Context.MODE_PRIVATE);
        long plantAt = prefs.getLong(KEY_PLANT_AT, 0);
        if (plantAt <= 0) {
            return null;
        }
        String plantBoot = prefs.getString(KEY_BOOT_ID, null);
        String boot = bootId();
        boolean sameUuid = boot != null && boot.equals(plantBoot);
        long plantedEpoch = prefs.getLong(KEY_BOOT_EPOCH, 0);
        boolean sameEpoch = plantedEpoch > 0
                && Math.abs(bootEpoch() - plantedEpoch) <= BOOT_WINDOW_MS;
        if (!sameUuid && !sameEpoch) {
            return null;
        }
        String build = prefs.getString(KEY_BUILD, "unknown");
        return context.getString(R.string.run_blocked_reason, build, time(plantAt));
    }

    static void markPlanted(Context context, String build) {
        String boot = bootId();
        context.getSharedPreferences(LEDGER, Context.MODE_PRIVATE).edit()
                .putString(KEY_BUILD, build)
                .putLong(KEY_PLANT_AT, System.currentTimeMillis())
                .putLong(KEY_BOOT_EPOCH, bootEpoch())
                .putString(KEY_BOOT_ID, boot)
                .apply();
    }

    static Begin begin(Context context, String build, boolean verified, int rev) {
        return begin(context, build, verified, rev, false);
    }

    static Begin begin(Context context, String build, boolean verified, int rev,
            boolean custom) {
        long now = System.currentTimeMillis();
        return new Begin(now + "-" + build, build, now, verified, rev, custom);
    }

    static void finish(Context context, Begin begin, String outcome, String detail,
            boolean root, boolean swapped) {
        long now = System.currentTimeMillis();
        RunRecord record = new RunRecord(begin.id, begin.build, outcome, detail, begin.rev,
                begin.startedAt, now, now - begin.startedAt, begin.verified, root, swapped,
                begin.custom);
        synchronized (LOCK) {
            List<String> lines = new ArrayList<>();
            lines.add(record.toJson().toString());
            for (RunRecord existing : history(context)) {
                lines.add(existing.toJson().toString());
            }
            while (lines.size() > MAX_RUNS) {
                lines.remove(lines.size() - 1);
            }
            StringBuilder out = new StringBuilder();
            for (String line : lines) {
                out.append(line).append('\n');
            }
            try {
                writeAtomic(historyFile(context), out.toString().getBytes(StandardCharsets.UTF_8));
            } catch (Throwable ignored) {
                // History is a convenience; never fail a run over it.
            }
        }
    }

    static List<RunRecord> history(Context context) {
        List<RunRecord> runs = new ArrayList<>();
        synchronized (LOCK) {
            try {
                String raw = readAll(historyFile(context));
                for (String line : raw.split("\n")) {
                    if (line.trim().isEmpty()) {
                        continue;
                    }
                    try {
                        runs.add(RunRecord.from(new JSONObject(line)));
                    } catch (Throwable ignored) {
                    }
                }
            } catch (Throwable ignored) {
            }
        }
        return runs;
    }

    static void clearHistory(Context context) {
        synchronized (LOCK) {
            File file = historyFile(context);
            if (file.exists()) {
                file.delete();
            }
        }
    }

    static String time(long millis) {
        return new SimpleDateFormat("MMM d, HH:mm", Locale.US).format(new Date(millis));
    }

    private static File historyFile(Context context) {
        return new File(context.getFilesDir(), HISTORY);
    }

    private static String bootId() {
        try {
            String value = readAll(new File("/proc/sys/kernel/random/boot_id")).trim();
            return value.isEmpty() ? null : value;
        } catch (Throwable t) {
            return null;
        }
    }

    /** Wall-clock time of this boot; used when the boot id cannot be read. */
    private static long bootEpoch() {
        return System.currentTimeMillis() - SystemClock.elapsedRealtime();
    }

    private static String readAll(File file) throws Exception {
        try (InputStream in = new FileInputStream(file);
                ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[16 * 1024];
            int read;
            while ((read = in.read(buffer)) > 0) {
                out.write(buffer, 0, read);
            }
            return out.toString(StandardCharsets.UTF_8.name());
        }
    }

    private static void writeAtomic(File file, byte[] data) throws Exception {
        File tmp = new File(file.getParentFile(), "." + file.getName() + ".tmp");
        try (FileOutputStream out = new FileOutputStream(tmp)) {
            out.write(data);
            out.getFD().sync();
        }
        if (file.exists() && !file.delete()) {
            throw new java.io.IOException("cannot replace " + file);
        }
        if (!tmp.renameTo(file)) {
            throw new java.io.IOException("cannot write " + file);
        }
    }
}
