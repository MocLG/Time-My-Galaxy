package dev.lukag.timemygalaxy;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.SharedPreferences;
import android.content.res.Configuration;
import android.os.Bundle;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowCompat;
import androidx.core.view.WindowInsetsCompat;

import com.google.android.material.appbar.MaterialToolbar;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** Lists the signed supported-build index, falling back to this build only. */
public class BuildsActivity extends AppCompatActivity {

    private static final String UI_PREFS = "wroot-ui";
    private static final String PREF_DARK = "dark";

    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private LinearLayout buildList;
    private TextView status;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        SharedPreferences prefs = getSharedPreferences(UI_PREFS, MODE_PRIVATE);
        boolean dark = prefs.contains(PREF_DARK)
                ? prefs.getBoolean(PREF_DARK, false)
                : (getResources().getConfiguration().uiMode
                        & Configuration.UI_MODE_NIGHT_MASK) == Configuration.UI_MODE_NIGHT_YES;
        setTheme(dark ? R.style.Theme_TMG_Dark : R.style.Theme_TMG);
        super.onCreate(savedInstanceState);
        WindowCompat.setDecorFitsSystemWindows(getWindow(), false);
        setContentView(R.layout.activity_builds);

        MaterialToolbar toolbar = findViewById(R.id.toolbar);
        toolbar.setNavigationOnClickListener(v -> finish());
        View root = findViewById(R.id.root);
        ViewCompat.setOnApplyWindowInsetsListener(root, (view, insets) -> {
            Insets bars = insets.getInsets(WindowInsetsCompat.Type.systemBars()
                    | WindowInsetsCompat.Type.displayCutout());
            view.setPadding(bars.left, bars.top, bars.right, bars.bottom);
            return insets;
        });

        buildList = findViewById(R.id.buildList);
        status = findViewById(R.id.status);
        load();
    }

    private void load() {
        final String current = DeviceGate.buildId();
        executor.execute(() -> {
            List<PayloadChannel.BuildEntry> entries = new ArrayList<>();
            String note;
            try {
                PayloadChannel.Index index = PayloadChannel.index(this, null);
                entries.addAll(index.builds);
                note = getString(R.string.builds_index_status, index.rev, entries.size(),
                        (index.cached ? getString(R.string.builds_saved_copy) : ""));
            } catch (Throwable t) {
                BuildInfo info = BuildInfo.from(null);
                entries.add(new PayloadChannel.BuildEntry(current, info.model, info.soc,
                        info.android, false, 0));
                note = getString(R.string.builds_index_unavailable, message(t));
            }
            final List<PayloadChannel.BuildEntry> rows = entries;
            final String text = note;
            runOnUiThread(() -> show(rows, text, current));
        });
    }

    private void show(List<PayloadChannel.BuildEntry> entries, String note, String current) {
        status.setText(note);
        buildList.removeAllViews();
        for (PayloadChannel.BuildEntry entry : entries) {
            View row = getLayoutInflater().inflate(R.layout.item_build, buildList, false);
            ((TextView) row.findViewById(R.id.buildName)).setText(entry.build);
            ((TextView) row.findViewById(R.id.buildDetail)).setText(entry.describe());
            TextView badge = row.findViewById(R.id.buildBadge);
            badge.setText(entry.verified ? R.string.verified : R.string.untested);
            badge.setTextColor(getColor(entry.verified ? R.color.tmg_good : R.color.tmg_bad));
            boolean cached = new File(getFilesDir(),
                    "payloads/" + entry.build + "/manifest.json").isFile();
            StringBuilder flags = new StringBuilder();
            if (entry.build.equals(current)) {
                flags.append(getString(R.string.build_current));
            }
            if (cached) {
                flags.append(flags.length() > 0 ? " · " : "").append(getString(R.string.build_cached));
            }
            if (flags.length() == 0) {
                flags.append(getString(R.string.build_tap_to_copy));
            }
            ((TextView) row.findViewById(R.id.buildFlags)).setText(flags.toString());
            row.setOnClickListener(v -> copy(entry.build));
            buildList.addView(row);
        }
    }

    private void copy(String build) {
        ClipboardManager clipboard = getSystemService(ClipboardManager.class);
        if (clipboard != null && build != null && !build.isEmpty()) {
            clipboard.setPrimaryClip(ClipData.newPlainText("build id", build));
            Toast.makeText(this, getString(R.string.copied, build), Toast.LENGTH_SHORT).show();
        }
    }

    private static String message(Throwable t) {
        String text = t.getMessage();
        return text == null || text.isEmpty() ? t.getClass().getSimpleName() : text;
    }

    @Override
    protected void onDestroy() {
        executor.shutdownNow();
        super.onDestroy();
    }
}
