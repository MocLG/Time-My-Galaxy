package dev.lukag.timemygalaxy;

import android.Manifest;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.content.res.Configuration;
import android.graphics.Typeface;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.Spannable;
import android.text.SpannableStringBuilder;
import android.text.TextPaint;
import android.text.method.LinkMovementMethod;
import android.text.style.ClickableSpan;
import android.text.style.ForegroundColorSpan;
import android.text.style.StyleSpan;
import android.text.style.UnderlineSpan;
import android.view.KeyEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.view.inputmethod.EditorInfo;
import android.view.inputmethod.InputMethodManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.content.FileProvider;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowCompat;
import androidx.core.view.WindowInsetsCompat;
import androidx.recyclerview.widget.RecyclerView;
import androidx.viewpager2.widget.ViewPager2;

import com.google.android.material.bottomnavigation.BottomNavigationView;
import com.google.android.material.card.MaterialCardView;
import com.google.android.material.color.MaterialColors;
import com.google.android.material.dialog.MaterialAlertDialogBuilder;
import com.google.android.material.materialswitch.MaterialSwitch;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Runs the SM-S731B timerfd exploit from the Shizuku shell user (uid 2000).
 *
 * The exploit parks forever once the helper has run, so the process is never
 * destroyed on success or when the activity closes. A planted run needs a
 * reboot to clean up; killing it can panic the kernel.
 */
public class MainActivity extends AppCompatActivity implements PayloadStore.Log {

    private static final int REQUEST_SHIZUKU = 0x5752;
    private static final String SHELL_PATH =
            "/product/bin:/apex/com.android.runtime/bin:/apex/com.android.art/bin:"
                    + "/apex/com.android.virt/bin:/system_ext/bin:/system/bin:/system/xbin:"
                    + "/odm/bin:/vendor/bin:/vendor/xbin";
    private static final long SUPERVISE_MS = 6 * 60 * 1000L;
    private static final long POLL_MS = 500L;
    private static final int LOG_LIMIT = 150_000;
    private static final String UI_PREFS = "wroot-ui";
    private static final String PREF_DARK = "dark";
    private static final String PREF_PAGE = "page";
    private static final String LOAD_LOG = PayloadStore.REMOTE_DIR + "/wr_load.log";
    private static final String EXEC_LOG = PayloadStore.REMOTE_DIR + "/wr_exec.log";
    private static final String RUN_LOG = PayloadStore.REMOTE_DIR + "/run.log";
    private static final String STAGED_KSUD = PayloadStore.REMOTE_DIR + "/ksud";
    private static final String ADB_KSUD = "/data/adb/ksud";

    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final Handler ui = new Handler(Looper.getMainLooper());
    private final AtomicBoolean busy = new AtomicBoolean();
    private final StringBuilder logBuffer = new StringBuilder();

    private ViewPager2 pager;
    private BottomNavigationView bottomNav;
    private TextView versionLine;

    private TextView shizukuChip;
    private TextView buildChip;
    private MaterialCardView gateCard;
    private TextView gateText;
    private MaterialCardView checksCard;
    private TextView checksText;
    private TextView logView;
    private ScrollView logScroll;
    private Button runButton;
    private Button copyButton;

    private TextView managerStatus;
    private TextView deviceInfo;
    private TextView updateStatus;
    private TextView aboutText;
    private Button repairButton;
    private Button buildsButton;
    private Button systemUiButton;
    private Button softRebootButton;
    private Button diagnosticsButton;
    private Button updateButton;
    private Button repoButton;
    private EditText commandInput;
    private Button commandButton;
    private Button checkButton;
    private TextView commandOutput;
    private MaterialSwitch darkSwitch;
    private MaterialSwitch providerSwitch;
    private TextView providerNote;

    private LinearLayout historyList;
    private TextView historyEmpty;
    private Button clearHistoryButton;

    private volatile Process tailProcess;
    private volatile String exploitPid;
    private volatile Targets.Target target;
    private volatile String payloadError;
    private DeviceGate.Result gateResult;

    private volatile boolean ksuReady;
    private boolean darkTheme;
    private boolean providerSync;
    private boolean followLogs = true;
    private boolean autoRequested;
    private int ansiDefaultColor = 0xFFF0F0F0;

    private boolean isDarkEnabled() {
        SharedPreferences prefs = getSharedPreferences(UI_PREFS, MODE_PRIVATE);
        if (prefs.contains(PREF_DARK)) {
            return prefs.getBoolean(PREF_DARK, false);
        }
        return (getResources().getConfiguration().uiMode & Configuration.UI_MODE_NIGHT_MASK)
                == Configuration.UI_MODE_NIGHT_YES;
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        darkTheme = isDarkEnabled();
        ansiDefaultColor = darkTheme ? 0xFFF2F2F2 : 0xFF111111;
        setTheme(darkTheme ? R.style.Theme_TMG_Dark : R.style.Theme_TMG);
        super.onCreate(savedInstanceState);
        WindowCompat.setDecorFitsSystemWindows(getWindow(), false);
        setContentView(R.layout.activity_main);

        bindChrome();
        applyInsets();
        gateResult = DeviceGate.check(null);
        target = null;

        appendLog("Time-My-Galaxy\n");
        appendLog("Transport: Shizuku shell (uid 2000)\n\n");
        refreshStatus();
        refreshVersionLine();
        resolvePayload(this::initialResolved);
        ui.postDelayed(this::autoRequestShizuku, 600);
    }

    @Override
    protected void onResume() {
        super.onResume();
        refreshVersionLine();
        refreshUpdateStatus();
        refreshStatus();
        if (pager != null && pager.getCurrentItem() == 2) {
            rebuildHistory();
        }
        autoRequestShizuku();
    }

    /** Asks for Shizuku as soon as the app opens, without the chip. */
    private void autoRequestShizuku() {
        if (autoRequested || busy.get()) {
            return;
        }
        if (!ShizukuBridge.isRunning() || ShizukuBridge.isGranted()) {
            return;
        }
        autoRequested = true;
        requestShizuku();
    }

    private void bindChrome() {
        pager = findViewById(R.id.pager);
        bottomNav = findViewById(R.id.bottomNav);
        versionLine = findViewById(R.id.versionLine);
        pager.setAdapter(new PagesAdapter());
        pager.setOffscreenPageLimit(2);
        pager.registerOnPageChangeCallback(new ViewPager2.OnPageChangeCallback() {
            @Override
            public void onPageSelected(int position) {
                bottomNav.getMenu().getItem(position).setChecked(true);
                getSharedPreferences(UI_PREFS, MODE_PRIVATE).edit()
                        .putInt(PREF_PAGE, position).apply();
                if (position == 1) {
                    refreshManagerStatus();
                    refreshDeviceInfo();
                    refreshUpdateStatus();
                } else if (position == 2) {
                    rebuildHistory();
                }
            }
        });
        bottomNav.setOnItemSelectedListener(item -> {
            int index = item.getItemId() == R.id.tab_exploit ? 0
                    : item.getItemId() == R.id.tab_tools ? 1 : 2;
            if (pager.getCurrentItem() != index) {
                pager.setCurrentItem(index, true);
            }
            return true;
        });
        int saved = getSharedPreferences(UI_PREFS, MODE_PRIVATE).getInt(PREF_PAGE, 0);
        bottomNav.getMenu().getItem(saved).setChecked(true);
        if (saved > 0) {
            pager.setCurrentItem(saved, false);
        }
        pager.post(this::refreshStatus);
    }

    private void applyInsets() {
        View root = findViewById(R.id.root);
        ViewCompat.setOnApplyWindowInsetsListener(root, (view, insets) -> {
            Insets bars = insets.getInsets(WindowInsetsCompat.Type.systemBars()
                    | WindowInsetsCompat.Type.displayCutout());
            view.setPadding(bars.left, bars.top, bars.right, bars.bottom);
            return insets;
        });
    }

    private final class PagesAdapter extends RecyclerView.Adapter<PagesAdapter.Holder> {

        @NonNull
        @Override
        public Holder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
            int layout = viewType == 0 ? R.layout.page_exploit
                    : viewType == 1 ? R.layout.page_tools : R.layout.page_history;
            View view = getLayoutInflater().inflate(layout, parent, false);
            if (viewType == 0) {
                bindExploitPage(view);
            } else if (viewType == 1) {
                bindToolsPage(view);
            } else {
                bindHistoryPage(view);
            }
            return new Holder(view);
        }

        @Override
        public void onBindViewHolder(@NonNull Holder holder, int position) {
        }

        @Override
        public int getItemCount() {
            return 3;
        }

        @Override
        public int getItemViewType(int position) {
            return position;
        }

        final class Holder extends RecyclerView.ViewHolder {
            Holder(View itemView) {
                super(itemView);
            }
        }
    }

    private void bindExploitPage(View view) {
        shizukuChip = view.findViewById(R.id.shizukuChip);
        buildChip = view.findViewById(R.id.buildChip);
        gateCard = view.findViewById(R.id.gateCard);
        gateText = view.findViewById(R.id.gateText);
        checksCard = view.findViewById(R.id.checksCard);
        checksText = view.findViewById(R.id.checksText);
        logScroll = view.findViewById(R.id.logScroll);
        logView = view.findViewById(R.id.logView);
        runButton = view.findViewById(R.id.runButton);
        copyButton = view.findViewById(R.id.copyButton);

        logView.setTextColor(ansiDefaultColor);
        logScroll.setOnScrollChangeListener((v, x, y, oldX, oldY) -> followLogs = isLogAtBottom());
        shizukuChip.setOnClickListener(v -> requestShizuku());
        buildChip.setOnClickListener(v -> refetchPayload());
        runButton.setOnClickListener(v -> confirmRun());
        copyButton.setOnClickListener(v -> copyLog());
        renderLogNow();
        refreshStatus();
    }

    private void bindToolsPage(View view) {
        managerStatus = view.findViewById(R.id.managerStatus);
        deviceInfo = view.findViewById(R.id.deviceInfo);
        updateStatus = view.findViewById(R.id.updateStatus);
        aboutText = view.findViewById(R.id.aboutText);
        repairButton = view.findViewById(R.id.repairButton);
        buildsButton = view.findViewById(R.id.buildsButton);
        systemUiButton = view.findViewById(R.id.systemUiButton);
        softRebootButton = view.findViewById(R.id.softRebootButton);
        diagnosticsButton = view.findViewById(R.id.diagnosticsButton);
        updateButton = view.findViewById(R.id.updateButton);
        repoButton = view.findViewById(R.id.repoButton);
        commandInput = view.findViewById(R.id.commandInput);
        commandOutput = view.findViewById(R.id.commandOutput);
        commandButton = view.findViewById(R.id.commandButton);
        checkButton = view.findViewById(R.id.checkButton);
        darkSwitch = view.findViewById(R.id.darkSwitch);
        providerSwitch = view.findViewById(R.id.providerSwitch);
        providerNote = view.findViewById(R.id.providerNote);

        repairButton.setOnClickListener(v -> repairManager());
        buildsButton.setOnClickListener(v ->
                startActivity(new Intent(this, BuildsActivity.class)));
        systemUiButton.setOnClickListener(v -> confirmRestartSystemUi());
        softRebootButton.setOnClickListener(v -> confirmSoftReboot());
        diagnosticsButton.setOnClickListener(v -> confirmDiagnostics());
        updateButton.setOnClickListener(v -> checkNow());
        repoButton.setOnClickListener(v -> openUrl(BuildConfig.REPO_URL));
        commandButton.setOnClickListener(v -> runRootCommand());
        checkButton.setOnClickListener(v -> runChecksNow());
        commandInput.setOnClickListener(v -> showKeyboard());
        commandInput.setOnFocusChangeListener((v, hasFocus) -> {
            if (hasFocus) {
                showKeyboard();
            }
        });
        commandInput.setOnEditorActionListener((v, actionId, event) -> {
            if (actionId == EditorInfo.IME_ACTION_GO
                    || (event != null && event.getKeyCode() == KeyEvent.KEYCODE_ENTER)) {
                hideKeyboard();
                runRootCommand();
                return true;
            }
            return false;
        });

        darkSwitch.setChecked(darkTheme);
        darkSwitch.setOnCheckedChangeListener((button, checked) -> {
            getSharedPreferences(UI_PREFS, MODE_PRIVATE).edit()
                    .putBoolean(PREF_DARK, checked).apply();
            recreate();
        });

        providerSwitch.setChecked(Provider.selected(this) == Provider.NEXT);
        providerSwitch.setOnCheckedChangeListener((button, checked) -> {
            if (providerSync) {
                return;
            }
            Provider wanted = checked ? Provider.NEXT : Provider.LEGACY;
            Targets.Target current = target;
            if (checked && (current == null
                    || !current.providers.contains(Provider.NEXT_ID))) {
                providerSync = true;
                providerSwitch.setChecked(false);
                providerSync = false;
                new MaterialAlertDialogBuilder(this)
                        .setTitle("KernelSU-Next not in this payload")
                        .setMessage("The loaded payload does not carry ksud-next. "
                                + "Refresh the payload (tap the build chip) or update "
                                + "the app first.")
                        .setPositiveButton("OK", null)
                        .show();
                return;
            }
            Provider.select(this, wanted);
            appendLog("[i] provider: " + wanted.label + " (" + wanted.versionName + ")\n");
            refreshManagerStatus();
            refreshStatus();
            checkStaged();
        });

        aboutText.setText("Time My Galaxy " + BuildConfig.VERSION_NAME
                + " (" + BuildConfig.VERSION_CODE + ")\nCommit " + BuildConfig.GIT_COMMIT
                + "\n" + BuildConfig.REPO_URL);
        refreshManagerStatus();
        refreshDeviceInfo();
        refreshUpdateStatus();
    }

    private void bindHistoryPage(View view) {
        historyList = view.findViewById(R.id.historyList);
        historyEmpty = view.findViewById(R.id.historyEmpty);
        clearHistoryButton = view.findViewById(R.id.clearHistoryButton);
        clearHistoryButton.setOnClickListener(v -> confirmClearHistory());
        rebuildHistory();
    }

    private void refreshStatus() {
        boolean running = ShizukuBridge.isRunning();
        boolean granted = running && ShizukuBridge.isGranted();
        String blocked = RunStore.blockReason(this);
        boolean hasPayload = target != null && target.dir != null;

        if (shizukuChip != null) {
            shizukuChip.setText("● " + (running
                    ? (granted ? "Shizuku ready" : "Shizuku permission")
                    : "Shizuku off"));
        }
        if (buildChip != null) {
            buildChip.setText(hasPayload
                    ? "● " + target.build + (target.verified ? "" : " · untested")
                    : "● No payload");
        }
        if (providerSwitch != null) {
            providerSwitch.setEnabled(!busy.get());
        }
        if (gateCard != null) {
            // The plant is marked at launch, so keep the warning hidden until
            // the run has finished instead of showing it mid-run.
            if (blocked != null && !busy.get()) {
                gateCard.setVisibility(View.VISIBLE);
                gateText.setText(blocked);
            } else if (!hasPayload && gateResult != null && !busy.get()) {
                gateCard.setVisibility(View.VISIBLE);
                gateText.setText(gateResult.detail);
            } else {
                gateCard.setVisibility(View.GONE);
            }
        }
        if (runButton != null) {
            runButton.setEnabled(!busy.get() && granted && hasPayload && blocked == null);
        }
        if (copyButton != null) {
            copyButton.setEnabled(logBuffer.length() > 0);
        }
        setEnabled(!busy.get(), repairButton, buildsButton, systemUiButton, softRebootButton,
                diagnosticsButton, updateButton, repoButton);
        if (commandButton != null) {
            commandButton.setEnabled(!busy.get() && granted);
            checkButton.setEnabled(!busy.get() && granted);
        }
        if (darkSwitch != null) {
            darkSwitch.setEnabled(!busy.get());
        }
    }

    private void setEnabled(boolean enabled, View... views) {
        for (View view : views) {
            if (view != null) {
                view.setEnabled(enabled);
            }
        }
    }

    private void refreshManagerStatus() {
        if (managerStatus == null) {
            return;
        }
        executor.execute(() -> {
            String status;
            try {
                status = ManagerPin.status((command, timeoutMs) ->
                        captureShell(command, timeoutMs, "/data/local/tmp"),
                        activeProvider());
            } catch (Throwable t) {
                status = "unavailable: " + message(t);
            }
            final String text = status;
            ui.post(() -> {
                if (managerStatus != null) {
                    managerStatus.setText(text);
                }
            });
        });
    }

    private void refreshDeviceInfo() {
        if (deviceInfo != null) {
            deviceInfo.setText(BuildInfo.from(target).describe());
        }
    }

    private void refreshUpdateStatus() {
        if (updateStatus == null) {
            return;
        }
        UpdateCheck.Latest latest = UpdateCheck.cached(this);
        if (latest == null) {
            updateStatus.setText("Not checked yet");
            return;
        }
        StringBuilder text = new StringBuilder(latest.tag)
                .append(" · checked ").append(RunStore.time(latest.checkedAt));
        if (UpdateCheck.isNewer(latest.tag)) {
            text.append(" · update available");
        } else {
            text.append(" · up to date");
        }
        updateStatus.setText(text.toString());
    }

    private void refreshVersionLine() {
        if (versionLine == null) {
            return;
        }
        SpannableStringBuilder line = new SpannableStringBuilder();
        String head = "Time My Galaxy " + BuildConfig.VERSION_NAME
                + " (" + BuildConfig.VERSION_CODE + ")";
        int start = line.length();
        line.append(head);
        addLink(line, start, line.length(), BuildConfig.REPO_URL);
        line.append(" · ");
        String commit = BuildConfig.GIT_COMMIT;
        start = line.length();
        line.append(commit);
        if (commit.matches("[0-9a-fA-F]{7,40}")) {
            addLink(line, start, line.length(), BuildConfig.REPO_URL + "/commit/" + commit);
        }
        UpdateCheck.Latest latest = UpdateCheck.cached(this);
        if (latest != null && UpdateCheck.isNewer(latest.tag)) {
            line.append(" · ");
            start = line.length();
            line.append("update ").append(latest.tag);
            addLink(line, start, line.length(), latest.url);
        }
        versionLine.setText(line);
        versionLine.setMovementMethod(LinkMovementMethod.getInstance());
    }

    private void addLink(SpannableStringBuilder text, int start, int end, String url) {
        ClickableSpan span = new ClickableSpan() {
            @Override
            public void onClick(@NonNull View widget) {
                openUrl(url);
            }

            @Override
            public void updateDrawState(@NonNull TextPaint paint) {
                paint.setColor(MaterialColors.getColor(versionLine,
                        com.google.android.material.R.attr.colorPrimary));
                paint.setUnderlineText(false);
            }
        };
        text.setSpan(span, start, end, Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
    }

    private void openUrl(String url) {
        try {
            startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(url)));
        } catch (Throwable t) {
            appendLog("[!] cannot open " + url + ": " + message(t) + "\n");
        }
    }

    private void checkNow() {
        if (busy.get()) {
            return;
        }
        executor.execute(() -> {
            setBusy(true);
            try {
                appendLog("[*] checking latest release\n");
                UpdateCheck.check(this, true, text -> appendLog(text + "\n"));
            } finally {
                setBusy(false);
                ui.post(() -> {
                    refreshUpdateStatus();
                    refreshVersionLine();
                });
            }
        });
    }

    private void initialResolved() {
        if (target == null) {
            showPayloadUnavailableDialog();
        } else {
            checkStaged();
        }
    }

    private void checkStaged() {
        Targets.Target current = target;
        executor.execute(() -> {
            boolean staged = current != null && current.dir != null
                    && ShizukuBridge.isRunning() && ShizukuBridge.isGranted()
                    && PayloadStore.isStaged(current.dir, current.build, activeProvider());
            ui.post(() -> appendLog(staged
                    ? "[+] payloads already staged in " + PayloadStore.REMOTE_DIR + "\n"
                    : "[*] payloads not staged yet\n"));
        });
    }

    /**
     * Resolves the payload for this build, then runs {@code then} on the UI
     * thread. The signed server manifest always wins when it is reachable;
     * the saved bundle is used when it is not.
     */
    private void resolvePayload(Runnable then) {
        executor.execute(() -> {
            setBusy(true);
            PayloadChannel.Resolution resolution = null;
            try {
                resolution = PayloadChannel.resolve(this, text -> appendLog(text));
            } catch (Throwable t) {
                appendLog("[-] payload setup failed: " + message(t) + "\n");
            }
            final PayloadChannel.Resolution resolved = resolution;
            ui.post(() -> {
                if (resolved != null) {
                    applyPayload(resolved);
                }
                setBusy(false);
                if (then != null) {
                    then.run();
                }
            });
        });
    }

    private void applyPayload(PayloadChannel.Resolution resolution) {
        payloadError = resolution.error;
        if (resolution.ok()) {
            target = resolution.target;
            appendLog("[+] payload " + target.build + " (" + target.describe() + "), "
                    + resolution.note + "\n");
        } else {
            target = null;
            appendLog("[-] no payload: "
                    + (resolution.error == null ? "unknown error" : resolution.error) + "\n");
        }
        gateResult = DeviceGate.check(target);
        refreshStatus();
        refreshDeviceInfo();
    }

    private void setBusy(boolean value) {
        Runnable apply = () -> {
            busy.set(value);
            getWindow().clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
            if (value) {
                getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
            }
            refreshStatus();
        };
        if (Looper.myLooper() == Looper.getMainLooper()) {
            apply.run();
        } else {
            ui.post(apply);
        }
    }

    private Provider activeProvider() {
        return Provider.selected(this);
    }

    private void requestShizuku() {
        if (!ShizukuBridge.isRunning()) {
            new MaterialAlertDialogBuilder(this)
                    .setTitle("Shizuku is not running")
                    .setMessage("Start Shizuku as the shell user first.\n\n"
                            + "Without a PC: pair through Shizuku's on-device wireless "
                            + "debugging flow and start the service. With a PC: run\n"
                            + "adb shell sh /storage/emulated/0/Android/data/"
                            + "moe.shizuku.privileged.api/start.sh\n\n"
                            + "The exploit always runs as uid 2000, never in the app sandbox.")
                    .setPositiveButton("OK", null)
                    .show();
            return;
        }
        ShizukuBridge.requestPermission(REQUEST_SHIZUKU, (granted, error) ->
                runOnUiThread(() -> {
                    appendLog(granted ? "[+] Shizuku permission granted\n"
                            : "[-] " + (error == null ? "Shizuku permission denied" : error)
                                    + "\n");
                    refreshStatus();
                }));
    }

    private void refetchPayload() {
        if (busy.get()) {
            return;
        }
        resolvePayload(() -> {
            Targets.Target current = target;
            if (current == null || current.dir == null) {
                showPayloadUnavailableDialog();
                return;
            }
            if (!current.verified) {
                new MaterialAlertDialogBuilder(this)
                        .setTitle("Untested payload")
                        .setMessage("Payload " + current.build + " is not verified on this "
                                + "firmware.\n\n"
                                + "Staging copies it into " + PayloadStore.REMOTE_DIR
                                + " and may not match the running kernel. Continue only if "
                                + "you built it for this exact build.")
                        .setNegativeButton("Cancel", null)
                        .setPositiveButton("Stage anyway", (d, w) -> stageNow(current))
                        .show();
                return;
            }
            stageNow(current);
        });
    }

    private void stageNow(Targets.Target current) {
        executor.execute(() -> {
            setBusy(true);
            try {
                appendLog("[*] staging payload " + current.build + " into "
                        + PayloadStore.REMOTE_DIR + "\n");
                PayloadStore.stageAll(current.dir, current.build, activeProvider(), this);
                appendLog("[+] staging complete\n");
            } catch (Throwable t) {
                appendLog("[-] staging failed: " + message(t) + "\n");
            } finally {
                setBusy(false);
            }
        });
    }

    private void confirmRun() {
        if (busy.get()) {
            return;
        }
        String blocked = RunStore.blockReason(this);
        if (blocked != null) {
            showLedgerDialog(blocked);
            return;
        }
        resolvePayload(() -> {
            Targets.Target current = target;
            if (current == null || current.dir == null) {
                showPayloadUnavailableDialog();
                return;
            }
            Provider run = activeProvider();
            String untested = current.verified ? "" : "\n\n"
                    + "WARNING: payload " + current.build + " is NOT verified on this "
                    + "firmware. An untested build can panic the kernel.";
            new MaterialAlertDialogBuilder(this)
                    .setTitle(current.verified ? "Run the exploit?"
                            : "Run the UNTESTED exploit?")
                    .setMessage("Target " + current.build + " (" + current.describe() + ").\n\n"
                            + "Provider " + run.label + " (" + run.versionName + ").\n\n"
                            + "Stages the payload, then runs wr_timerfd as uid 2000 (Shizuku shell).\n\n"
                            + "- One plant per boot. If this boot already ran it, reboot first.\n"
                            + "- Takes roughly 30-60 s; keep the screen on and leave the phone alone.\n"
                            + "- On success the process parks forever and must not be killed.\n"
                            + "- A failed plant also needs a reboot, and either can panic the kernel.\n\n"
                            + "Run only on a device you own." + untested)
                    .setNegativeButton("Cancel", null)
                    .setPositiveButton(current.verified ? "Run" : "Run anyway", (d, w) ->
                            executeExploit())
                    .show();
        });
    }

    private void executeExploit() {
        if (busy.get()) {
            return;
        }
        if (!ShizukuBridge.isRunning() || !ShizukuBridge.isGranted()) {
            requestShizuku();
            return;
        }
        if (RunStore.blockReason(this) != null) {
            showLedgerDialog(RunStore.blockReason(this));
            return;
        }
        if (android.os.Build.VERSION.SDK_INT >= 33
                && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED) {
            appendLog("[i] notifications are off; the run notification may be hidden\n");
        }
        executor.execute(() -> {
            setBusy(true);
            Process tail = null;
            RunStore.Begin record = null;
            long startedAt = System.currentTimeMillis();
            boolean planted = false;
            boolean swapped = false;
            String outcome = "error";
            String detail = "";
            try {
                Targets.Target current = target;
                Provider run = activeProvider();
                if (current == null || current.dir == null) {
                    appendLog("[-] no payload for this firmware\n");
                    outcome = "no payload";
                    return;
                }
                String blocked = RunStore.blockReason(this);
                if (blocked != null) {
                    appendLog("[!] " + blocked.replace("\n\n", " ") + "\n");
                    outcome = "blocked";
                    return;
                }
                RunService.start(this, current.build);
                RunService.update("Staging payload " + current.build);

                appendLog("[*] staging payload " + current.build + " (" + run.label
                        + ") before running\n");
                PayloadStore.stageAll(current.dir, current.build, run, this);

                String parked = readPidOrNull();
                if (parked == null) {
                    appendLog("[-] lost Shizuku before planting\n");
                    outcome = "lost";
                    return;
                }
                if (!parked.isEmpty()) {
                    appendLog("[-] wr_timerfd already running: pid " + parked + "\n");
                    appendLog("[i] a planted run is cleaned only by reboot\n");
                    outcome = "already parked";
                    return;
                }

                String cleared = captureShell("rm -f " + quote(LOAD_LOG) + " "
                        + quote(EXEC_LOG) + " " + quote(RUN_LOG)
                        + "; if [ -e " + quote(LOAD_LOG) + " ] || [ -e " + quote(RUN_LOG)
                        + " ]; then echo stale; else touch " + quote(RUN_LOG)
                        + " && echo cleaned; fi", 8000L).trim();
                if (!cleared.contains("cleaned")) {
                    appendLog("[-] cannot clear old logs: "
                            + (cleared.isEmpty() ? "no output" : cleared) + "\n");
                    outcome = "log clear failed";
                    return;
                }

                // Best effort; never gates the run.
                try {
                    ManagerPin.Result pin = ManagerPin.ensure(
                            getFilesDir(), run,
                            (command, timeoutMs) ->
                                    captureShell(command, timeoutMs, "/data/local/tmp"),
                            text -> appendLog(text + "\n"));
                    swapped = pin.swapped;
                    if (!pin.pinned) {
                        appendLog("[i] manager: continuing with the exploit\n");
                    }
                } catch (Throwable t) {
                    appendLog("[!] manager: step failed: " + message(t) + "\n");
                }

                String[] env = new String[]{
                        "PATH=" + SHELL_PATH,
                        "HOME=" + PayloadStore.REMOTE_DIR,
                        "TK_SPRAY=socket",
                };
                // New session + file-backed stdio: neither Shizuku's process
                // group nor its log pipe can end the exploit when it restarts.
                String launch = "cd " + quote(PayloadStore.REMOTE_DIR)
                        + " && trap '' 1 13"
                        + " && if command -v setsid >/dev/null 2>&1"
                        + " && setsid true 2>/dev/null; then"
                        + " echo 'launcher: setsid' >> " + quote(RUN_LOG) + ";"
                        + " setsid ./wr_timerfd >> " + quote(RUN_LOG)
                        + " 2>&1 < /dev/null &"
                        + " else echo 'launcher: fallback' >> " + quote(RUN_LOG) + ";"
                        + " ./wr_timerfd >> " + quote(RUN_LOG)
                        + " 2>&1 < /dev/null & fi";
                appendLog("[*] planting wr_timerfd detached from Shizuku\n");
                record = RunStore.begin(this, current.build, current.verified, current.rev);
                RunStore.markPlanted(this, current.build);
                planted = true;
                RunService.update("Planting wr_timerfd");
                Process launcher = ShizukuBridge.exec(
                        new String[]{"/system/bin/sh", "-c", launch},
                        env, PayloadStore.REMOTE_DIR);
                pump(launcher.getInputStream(), "launch");
                pump(launcher.getErrorStream(), "launch-err");
                long launchDeadline = System.currentTimeMillis() + 10000;
                while (launcher.isAlive() && System.currentTimeMillis() < launchDeadline) {
                    Thread.sleep(100);
                }
                if (launcher.isAlive()) {
                    appendLog("[!] launcher did not exit\n");
                }

                String pid = "";
                boolean unknown = false;
                long waitStart = System.currentTimeMillis();
                while (System.currentTimeMillis() - waitStart < 15000) {
                    String now = readPidOrNull();
                    if (now == null) {
                        unknown = true;
                    } else if (!now.isEmpty()) {
                        pid = now;
                        break;
                    }
                    Thread.sleep(300);
                }
                if (pid.isEmpty()) {
                    appendLog(unknown
                            ? "[-] cannot see wr_timerfd; Shizuku is unavailable\n"
                            : "[-] wr_timerfd did not start\n");
                    outcome = "did not start";
                    RunService.update("wr_timerfd did not start");
                    String runTail = captureShell("tail -c 4096 " + quote(RUN_LOG)
                            + " 2>/dev/null", 5000L);
                    if (!runTail.trim().isEmpty() && !runTail.startsWith("error:")) {
                        appendLog("[i] run.log:\n" + runTail.trim() + "\n");
                    }
                    return;
                }
                exploitPid = pid;
                appendLog("[i] pid " + pid + " oom_score_adj " + readAdj(pid) + "\n");
                appendLog("[i] detached: own session, stdout in " + RUN_LOG + "\n");

                try {
                    tail = ShizukuBridge.exec(new String[]{"/system/bin/sh", "-c",
                                    "trap '' 1 13; exec tail -n +1 -f " + quote(RUN_LOG)},
                            null, PayloadStore.REMOTE_DIR);
                    tailProcess = tail;
                    pump(tail.getInputStream(), "out");
                    pump(tail.getErrorStream(), "err");
                } catch (Throwable t) {
                    appendLog("[!] live log unavailable: " + message(t) + "\n");
                }

                long runStartedAt = System.currentTimeMillis();
                String logTail = "";
                boolean done = false;
                boolean alive = true;
                boolean lost = false;
                long lastPidCheck = 0;
                long lastNotify = 0;
                while (true) {
                    logTail = captureShell("tail -c 4096 " + quote(LOAD_LOG)
                            + " 2>/dev/null", 8000L);
                    if (!logTail.startsWith("error:") && logTail.contains("done")) {
                        done = true;
                        break;
                    }
                    if (System.currentTimeMillis() - runStartedAt > SUPERVISE_MS) {
                        break;
                    }
                    if (System.currentTimeMillis() - lastNotify >= 5000) {
                        lastNotify = System.currentTimeMillis();
                        RunService.update("Waiting for done ("
                                + (System.currentTimeMillis() - startedAt) / 1000 + "s)");
                    }
                    if (System.currentTimeMillis() - lastPidCheck >= 2000) {
                        lastPidCheck = System.currentTimeMillis();
                        String now = readPidOrNull();
                        if (now == null) {
                            if (!lost) {
                                appendLog("[!] Shizuku unavailable; exploit is detached, "
                                        + "supervision paused\n");
                                lost = true;
                            }
                        } else if (now.isEmpty()) {
                            Thread.sleep(300);
                            now = readPidOrNull();
                            if (now != null && now.isEmpty()) {
                                alive = false;
                                break;
                            }
                            if (now != null) {
                                exploitPid = now;
                                lost = false;
                            }
                        } else {
                            exploitPid = now;
                            lost = false;
                        }
                    }
                    Thread.sleep(POLL_MS);
                }

                long elapsed = (System.currentTimeMillis() - runStartedAt) / 1000;
                if (!done) {
                    logTail = captureShell("tail -c 4096 " + quote(LOAD_LOG)
                            + " 2>/dev/null", 8000L);
                    done = !logTail.startsWith("error:") && logTail.contains("done");
                }

                if (done) {
                    outcome = "done";
                    appendLog("[+] helper reached done after " + elapsed + "s\n");
                    String id = captureShell("su -c " + quote("id"), 20000L).trim();
                    appendLog("[*] su -c id: " + id + "\n");
                    if (id.contains("uid=0")) {
                        ksuReady = true;
                        appendLog("[+] KernelSU root is live\n");
                        hardenParkedProcess();
                    } else {
                        appendLog("[!] helper finished but su did not return uid=0\n");
                    }
                    appendLog("[i] exploit stays parked until reboot; do not kill it\n");
                    RunService.update("Run done, checking root");
                    RunChecks.Result checks = RunChecks.run(run,
                            text -> appendLog(text + "\n"));
                    appendLog(checks.text() + "\n");
                    detail = checks.oneLine();
                    ui.post(() -> showChecks(checks.text()));
                } else if (!alive) {
                    outcome = "vanished";
                    appendLog("[-] wr_timerfd disappeared before done after "
                            + elapsed + "s\n");
                    if (!logTail.trim().isEmpty() && !logTail.startsWith("error:")) {
                        appendLog("[i] helper log tail:\n" + logTail.trim() + "\n");
                    }
                    appendLog("[i] reboot before trying again\n");
                    detail = "process vanished before done";
                } else if (lost) {
                    outcome = "lost";
                    appendLog("[!] lost Shizuku for " + elapsed
                            + "s; the exploit is detached and may still be running\n");
                    appendLog("[i] do not replant; reboot if you want to retry\n");
                    detail = "lost Shizuku during supervision";
                } else {
                    outcome = "timeout";
                    appendLog("[!] no done after " + elapsed + "s; exploit still running\n");
                    appendLog("[i] leave it parked and reboot when you want to retry\n");
                    if (!logTail.trim().isEmpty() && !logTail.startsWith("error:")) {
                        appendLog("[i] helper log tail:\n" + logTail.trim() + "\n");
                    }
                    detail = "no done after " + elapsed + "s";
                }
            } catch (Throwable t) {
                outcome = "error";
                detail = message(t);
                appendLog("[-] run failed: " + message(t) + "\n");
            } finally {
                if (tail != null) {
                    try {
                        Thread.sleep(500);
                    } catch (InterruptedException ignored) {
                    }
                    if (tail.isAlive()) {
                        tail.destroy();
                    }
                    tailProcess = null;
                }
                if (planted && record != null) {
                    RunStore.finish(this, record, outcome, detail, ksuReady, swapped);
                    ui.post(this::rebuildHistory);
                }
                RunService.stop(this);
                setBusy(false);
            }
        });
    }

    private void showChecks(String text) {
        if (checksText == null) {
            return;
        }
        checksText.setText(text);
        checksCard.setVisibility(View.VISIBLE);
    }

    private void showCommandOutput(String text) {
        if (commandOutput == null) {
            return;
        }
        commandOutput.setText(text);
        commandOutput.setVisibility(text.isEmpty() ? View.GONE : View.VISIBLE);
    }

    private void runChecksNow() {
        if (busy.get()) {
            return;
        }
        if (!ShizukuBridge.isRunning() || !ShizukuBridge.isGranted()) {
            requestShizuku();
            return;
        }
        executor.execute(() -> {
            setBusy(true);
            try {
                appendLog("[*] running root checks\n");
                RunChecks.Result checks = RunChecks.run(activeProvider(),
                        text -> appendLog(text + "\n"));
                appendLog(checks.text() + "\n");
                if (checks.root()) {
                    ksuReady = true;
                }
                ui.post(() -> {
                    showChecks(checks.text());
                    showCommandOutput(checks.text());
                });
            } catch (Throwable t) {
                appendLog("[-] checks failed: " + message(t) + "\n");
            } finally {
                setBusy(false);
                ui.post(this::refreshStatus);
            }
        });
    }

    private void repairManager() {
        if (busy.get()) {
            return;
        }
        if (!ShizukuBridge.isRunning() || !ShizukuBridge.isGranted()) {
            requestShizuku();
            return;
        }
        executor.execute(() -> {
            setBusy(true);
            try {
                ManagerPin.Result result = ManagerPin.ensure(
                        getFilesDir(), activeProvider(),
                        (command, timeoutMs) ->
                                captureShell(command, timeoutMs, "/data/local/tmp"),
                        text -> appendLog(text + "\n"));
                appendLog("[i] manager: " + (result.pinned ? "pinned" : "not pinned")
                        + " (" + result.detail + ")\n");
            } catch (Throwable t) {
                appendLog("[!] manager: step failed: " + message(t) + "\n");
            } finally {
                setBusy(false);
                ui.post(this::refreshManagerStatus);
            }
        });
    }

    private void confirmRestartSystemUi() {
        if (busy.get()) {
            return;
        }
        if (!ShizukuBridge.isRunning() || !ShizukuBridge.isGranted()) {
            requestShizuku();
            return;
        }
        new MaterialAlertDialogBuilder(this)
                .setTitle("Restart SystemUI?")
                .setMessage("This needs root and restarts com.android.systemui so the "
                        + "interface reloads.\n\n"
                        + "It does not touch a parked exploit. The screen may go black "
                        + "for a moment and the lock screen may appear.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Restart", (d, w) -> restartSystemUi())
                .show();
    }

    /**
     * Shell uid 2000 cannot kill the system UI, so this runs su and refuses to
     * act unless su confirms uid 0. The parked exploit is left untouched.
     */
    private void restartSystemUi() {
        executor.execute(() -> {
            setBusy(true);
            try {
                String id = captureShell("su -c " + quote("id"), 20000L).trim();
                appendLog("[*] su -c id: " + id + "\n");
                if (!id.contains("uid=0")) {
                    ksuReady = false;
                    appendLog("[-] restart SystemUI needs root; su did not return uid=0\n");
                    ui.post(() -> new MaterialAlertDialogBuilder(this)
                            .setTitle("Root required")
                            .setMessage("Restarting SystemUI only works with root, and su did "
                                    + "not return uid=0 on this boot.\n\n"
                                    + "Run the exploit first and confirm root with "
                                    + "\"Run checks\".")
                            .setPositiveButton("OK", null)
                            .show());
                    return;
                }
                ksuReady = true;
                appendLog("[*] restarting com.android.systemui\n");
                String out = captureShell(
                        "su -c " + quote("kill -9 $(pidof com.android.systemui)"), 15000L);
                if (!out.trim().isEmpty() && !out.startsWith("error:")) {
                    appendLog(out.trim() + "\n");
                }
                Thread.sleep(2000);
                String pid = captureShell("pidof com.android.systemui 2>/dev/null", 5000L).trim();
                if (pid.matches("\\d+")) {
                    appendLog("[+] SystemUI restarted, pid " + pid + "\n");
                } else {
                    appendLog("[!] SystemUI pid not visible; check the screen\n");
                }
            } catch (Throwable t) {
                appendLog("[-] restart failed: " + message(t) + "\n");
            } finally {
                setBusy(false);
                ui.post(this::refreshStatus);
            }
        });
    }

    private void confirmSoftReboot() {
        if (busy.get()) {
            return;
        }
        if (!ShizukuBridge.isRunning() || !ShizukuBridge.isGranted()) {
            requestShizuku();
            return;
        }
        new MaterialAlertDialogBuilder(this)
                .setTitle("Soft reboot?")
                .setMessage("This runs the same soft reboot as KernelSU Manager "
                        + "(ksud soft-reboot).\n\n"
                        + "Android's userspace stops and starts again: all apps close, the "
                        + "screen goes black, and the lock screen appears.\n\n"
                        + "The kernel is not rebooted and root stays loaded. A parked exploit "
                        + "stays parked, and this boot's ledger entry is not cleared.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Soft reboot", (d, w) -> softReboot())
                .show();
    }

    private void softReboot() {
        executor.execute(() -> {
            setBusy(true);
            try {
                String id = captureShell("su -c " + quote("id"), 20000L).trim();
                appendLog("[*] su -c id: " + id + "\n");
                if (!id.contains("uid=0")) {
                    ksuReady = false;
                    appendLog("[-] soft reboot needs root; su did not return uid=0\n");
                    ui.post(() -> new MaterialAlertDialogBuilder(this)
                            .setTitle("Root required")
                            .setMessage("The KernelSU soft reboot needs root, and su did not "
                                    + "return uid=0 on this boot.\n\n"
                                    + "Run the exploit first.")
                            .setPositiveButton("OK", null)
                            .show());
                    return;
                }
                ksuReady = true;
                String binary = null;
                if (captureShell("test -x " + quote(STAGED_KSUD)
                        + " && echo yes || echo no", 15000L).contains("yes")) {
                    binary = STAGED_KSUD;
                } else if (captureShell("su -c " + quote("test -x " + ADB_KSUD
                        + " && echo yes || echo no"), 15000L).contains("yes")) {
                    binary = ADB_KSUD;
                }
                if (binary == null) {
                    appendLog("[-] soft reboot: no ksud binary found\n");
                    return;
                }
                appendLog("[*] soft reboot: " + binary + " soft-reboot\n");
                appendLog("[i] the framework restarts; the kernel boot id does not change\n");
                String out = captureShell("su -c " + quote(binary + " soft-reboot"), 30000L);
                if (out.contains("failed") || out.contains("denied")
                        || out.startsWith("error:")) {
                    appendLog("[!] soft reboot said: " + out.trim() + "\n");
                    appendLog("[i] not retrying\n");
                } else if (!out.trim().isEmpty()) {
                    appendLog(out.trim() + "\n");
                }
            } catch (Throwable t) {
                appendLog("[-] soft reboot failed: " + message(t) + "\n");
            } finally {
                setBusy(false);
            }
        });
    }

    private void confirmDiagnostics() {
        new MaterialAlertDialogBuilder(this)
                .setTitle("Export diagnostics?")
                .setMessage("Writes every log from " + PayloadStore.REMOTE_DIR
                        + " and this session's app log to one text file, then opens the "
                        + "share sheet.\n\n"
                        + "Nothing is trimmed or capped. Works without root; root adds the "
                        + "files that only su can read.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Export", (d, w) -> exportDiagnostics())
                .show();
    }

    private void exportDiagnostics() {
        final String session = logBuffer.toString();
        final String header = diagnosticsHeader();
        executor.execute(() -> {
            setBusy(true);
            try {
                File file = Diagnostics.export(this, header, session, ksuReady,
                        text -> appendLog(text + "\n"));
                ui.post(() -> shareFile(file));
            } catch (Throwable t) {
                appendLog("[-] diagnostics failed: " + message(t) + "\n");
            } finally {
                setBusy(false);
            }
        });
    }

    private String diagnosticsHeader() {
        StringBuilder out = new StringBuilder();
        out.append("Time My Galaxy diagnostics\n");
        out.append("generated ").append(RunStore.time(System.currentTimeMillis())).append('\n');
        out.append("app ").append(BuildConfig.VERSION_NAME).append(" (")
                .append(BuildConfig.VERSION_CODE).append(")\n");
        out.append("commit ").append(BuildConfig.GIT_COMMIT).append('\n');
        out.append(BuildInfo.from(target).describe()).append('\n');
        out.append("shizuku ").append(ShizukuBridge.isRunning()
                ? (ShizukuBridge.isGranted() ? "granted" : "running, no permission") : "off")
                .append('\n');
        out.append("manager ").append(managerStatus == null ? "?" : managerStatus.getText())
                .append('\n');
        Provider provider = activeProvider();
        out.append("provider ").append(provider.label).append(' ')
                .append(provider.versionName).append('\n');
        out.append("ledger ")
                .append(RunStore.blockReason(this) == null ? "clear" : "blocked this boot")
                .append('\n');
        out.append("\n== last runs ==\n");
        List<RunStore.RunRecord> runs = RunStore.history(this);
        for (int i = 0; i < runs.size() && i < 10; i++) {
            RunStore.RunRecord run = runs.get(i);
            out.append(RunStore.time(run.startedAt)).append("  ").append(run.build)
                    .append("  ").append(run.outcome).append("  ").append(run.meta());
            if (run.detail != null && !run.detail.isEmpty()) {
                out.append("\n    ").append(run.detail);
            }
            out.append('\n');
        }
        if (runs.isEmpty()) {
            out.append("none\n");
        }
        out.append("\n== last checks ==\n");
        out.append(checksText == null || checksText.getText().length() == 0
                ? "none" : checksText.getText().toString());
        return out.toString();
    }

    private void shareFile(File file) {
        try {
            Uri uri = FileProvider.getUriForFile(this, getPackageName() + ".files", file);
            Intent send = new Intent(Intent.ACTION_SEND)
                    .setType("text/plain")
                    .putExtra(Intent.EXTRA_STREAM, uri)
                    .putExtra(Intent.EXTRA_SUBJECT, "Time My Galaxy diagnostics")
                    .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
            startActivity(Intent.createChooser(send, "Share diagnostics"));
        } catch (Throwable t) {
            appendLog("[!] share failed: " + message(t) + "\n");
            appendLog("[i] file kept at " + file.getAbsolutePath() + "\n");
        }
    }

    private void runRootCommand() {
        if (busy.get()) {
            return;
        }
        if (!ShizukuBridge.isRunning() || !ShizukuBridge.isGranted()) {
            requestShizuku();
            return;
        }
        String command = commandInput.getText().toString().trim();
        if (command.isEmpty()) {
            command = "id";
        }
        final String finalCommand = command;
        hideKeyboard();
        executor.execute(() -> {
            setBusy(true);
            try {
                appendLog("$ su -c " + finalCommand + "\n");
                ui.post(() -> showCommandOutput("$ su -c " + finalCommand + "\nRunning…"));
                String out = captureShell("su -c " + ShizukuBridge.shellQuote(finalCommand),
                        20000L);
                appendLog(out.endsWith("\n") || out.isEmpty() ? out : out + "\n");
                ui.post(() -> showCommandOutput("$ su -c " + finalCommand + "\n"
                        + (out.isEmpty() ? "(no output)" : out)));
                if (out.contains("uid=0")) {
                    ksuReady = true;
                    ui.post(this::refreshStatus);
                }
            } finally {
                setBusy(false);
            }
        });
    }

    private void copyLog() {
        List<AnsiLog.Run> runs = AnsiLog.parse(logBuffer, ansiDefaultColor, darkTheme);
        StringBuilder text = new StringBuilder();
        for (AnsiLog.Run run : runs) {
            text.append(run.text);
        }
        ClipboardManager clipboard = getSystemService(ClipboardManager.class);
        if (clipboard == null) {
            return;
        }
        clipboard.setPrimaryClip(ClipData.newPlainText("Time My Galaxy log", text));
        Toast.makeText(this, "Log copied", Toast.LENGTH_SHORT).show();
    }

    private void rebuildHistory() {
        if (historyList == null) {
            return;
        }
        List<RunStore.RunRecord> runs = RunStore.history(this);
        historyList.removeAllViews();
        historyEmpty.setVisibility(runs.isEmpty() ? View.VISIBLE : View.GONE);
        clearHistoryButton.setVisibility(runs.isEmpty() ? View.GONE : View.VISIBLE);
        for (RunStore.RunRecord run : runs) {
            View item = getLayoutInflater().inflate(R.layout.item_run, historyList, false);
            TextView outcome = item.findViewById(R.id.runOutcome);
            outcome.setText(run.outcome);
            outcome.setTextColor(getColor("done".equals(run.outcome)
                    ? R.color.tmg_good : R.color.tmg_bad));
            ((TextView) item.findViewById(R.id.runBuild)).setText(run.build);
            ((TextView) item.findViewById(R.id.runWhen)).setText(RunStore.time(run.startedAt));
            TextView detail = item.findViewById(R.id.runDetail);
            detail.setText(run.detail == null || run.detail.isEmpty() ? "No detail" : run.detail);
            ((TextView) item.findViewById(R.id.runMeta)).setText(run.meta());
            historyList.addView(item);
        }
    }

    private void confirmClearHistory() {
        new MaterialAlertDialogBuilder(this)
                .setTitle("Clear history?")
                .setMessage("Removes the saved run cards. The boot ledger and the logs in "
                        + PayloadStore.REMOTE_DIR + " are not touched.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Clear", (d, w) -> {
                    RunStore.clearHistory(this);
                    rebuildHistory();
                })
                .show();
    }

    private void showLedgerDialog(String message) {
        new MaterialAlertDialogBuilder(this)
                .setTitle("Reboot required")
                .setMessage(message)
                .setPositiveButton("OK", null)
                .show();
    }

    private void showKeyboard() {
        if (commandInput == null) {
            return;
        }
        commandInput.requestFocus();
        InputMethodManager ime = getSystemService(InputMethodManager.class);
        if (ime != null) {
            ime.showSoftInput(commandInput, InputMethodManager.SHOW_IMPLICIT);
        }
    }

    private void hideKeyboard() {
        InputMethodManager ime = getSystemService(InputMethodManager.class);
        if (ime != null && commandInput != null) {
            ime.hideSoftInputFromWindow(commandInput.getWindowToken(), 0);
        }
    }

    /**
     * Root can exempt the parked process from LMKD and turn the panic on a
     * killed run into a dead task. It does not make the process immortal:
     * root/shell SIGKILL still ends it and reboot still cleans it.
     */
    private void hardenParkedProcess() {
        disablePanicOnOops();
        String pid = readPidOrNull();
        if ((pid == null || pid.isEmpty()) && exploitPid != null
                && exploitPid.matches("\\d+")) {
            pid = exploitPid;
        }
        if (pid == null || pid.isEmpty()) {
            appendLog("[!] parked pid not found; cannot lower oom_score_adj\n");
            return;
        }
        String before = readAdj(pid);
        captureShell("su -c " + quote("echo -1000 > /proc/" + pid + "/oom_score_adj"),
                15000L);
        String after = readAdj(pid);
        appendLog("[i] parked pid " + pid + " oom_score_adj " + before
                + " -> " + after + "\n");
        if (!"-1000".equals(after)) {
            appendLog("[!] oom_score_adj not lowered; avoid memory pressure while parked\n");
        }
    }

    /**
     * A parked run that is killed oopses in free_pipe_info() while the kernel
     * tears down the fake pipe, and panic_on_oops turns that into a reboot.
     * Clearing the sysctl makes the kernel park the exiting task as
     * TASK_DEAD (shown as state X) instead, so the phone stays up and this
     * boot's root survives. Global and per-boot: a reboot restores the
     * built-in value of 1.
     */
    private void disablePanicOnOops() {
        String before = captureShell(
                "su -c " + quote("cat /proc/sys/kernel/panic_on_oops"), 15000L).trim();
        captureShell("su -c " + quote("echo 0 > /proc/sys/kernel/panic_on_oops"),
                15000L);
        String after = captureShell(
                "su -c " + quote("cat /proc/sys/kernel/panic_on_oops"), 15000L).trim();
        appendLog("[i] panic_on_oops " + before + " -> " + after + "\n");
        if (!"0".equals(after)) {
            appendLog("[!] panic_on_oops is not 0; killing the parked run will reboot\n");
        }
    }

    /**
     * null means Shizuku could not be reached, empty means the process is gone.
     */
    private String readPidOrNull() {
        String out = captureShell("pidof wr_timerfd timer_s25fe 2>/dev/null", 5000L).trim();
        if (out.startsWith("error:")) {
            return null;
        }
        for (String part : out.split("\\s+")) {
            if (part.matches("\\d+")) {
                return part;
            }
        }
        return "";
    }

    private String readAdj(String pid) {
        String out = captureShell("cat /proc/" + pid + "/oom_score_adj 2>/dev/null",
                5000L).trim();
        return out.isEmpty() || out.startsWith("error:") ? "?" : out;
    }

    private static String quote(String value) {
        return ShizukuBridge.shellQuote(value);
    }

    private String captureShell(String command, long timeoutMs) {
        return captureShell(command, timeoutMs, PayloadStore.REMOTE_DIR);
    }

    /** Runs a shell command through Shizuku with a timeout, merging stdout/stderr. */
    private String captureShell(String command, long timeoutMs, String dir) {
        return Shell.capture(command, timeoutMs, dir, text -> appendLog(text + "\n")).out;
    }

    private Thread pump(InputStream stream, String tag) {
        Thread thread = new Thread(() -> {
            byte[] buffer = new byte[8192];
            try {
                int read;
                while ((read = stream.read(buffer)) > 0) {
                    String text = new String(buffer, 0, read);
                    ui.post(() -> appendLog(text));
                }
            } catch (IOException ignored) {
            }
        }, "payload-" + tag);
        thread.setDaemon(true);
        thread.start();
        return thread;
    }

    private void showPayloadUnavailableDialog() {
        StringBuilder message = new StringBuilder();
        if (gateResult != null) {
            message.append(gateResult.detail).append("\n\n");
        }
        message.append("No payload is available for this firmware build.\n\n")
                .append("Connect to the internet and try again. If this build is not "
                        + "supported yet, there is nothing to download.\n\n")
                .append("The bundle is downloaded once and then kept for offline use.");
        if (payloadError != null) {
            message.append("\n\nLast error: ").append(payloadError);
        }
        new MaterialAlertDialogBuilder(this)
                .setTitle("Payload not available")
                .setMessage(message.toString())
                .setPositiveButton("OK", null)
                .show();
    }

    @Override
    public void line(String text) {
        appendLog(text + "\n");
    }

    private void appendLog(String text) {
        ui.post(() -> {
            logBuffer.append(text);
            if (logBuffer.length() > LOG_LIMIT) {
                logBuffer.delete(0, logBuffer.length() - LOG_LIMIT / 2);
                logBuffer.insert(0, "[... earlier output dropped ...]\n");
            }
            renderLogNow();
        });
    }

    private void renderLogNow() {
        if (logView == null) {
            return;
        }
        boolean follow = followLogs;
        logView.setText(renderLog());
        if (follow) {
            logScroll.post(() -> logScroll.scrollTo(0, logView.getBottom()));
        }
    }

    private CharSequence renderLog() {
        SpannableStringBuilder out = new SpannableStringBuilder();
        for (AnsiLog.Run run : AnsiLog.parse(logBuffer, ansiDefaultColor, darkTheme)) {
            int start = out.length();
            out.append(run.text);
            int end = out.length();
            if (run.color != ansiDefaultColor) {
                out.setSpan(new ForegroundColorSpan(run.color), start, end,
                        Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
            }
            if (run.bold) {
                out.setSpan(new StyleSpan(Typeface.BOLD), start, end,
                        Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
            }
            if (run.italic) {
                out.setSpan(new StyleSpan(Typeface.ITALIC), start, end,
                        Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
            }
            if (run.underline) {
                out.setSpan(new UnderlineSpan(), start, end,
                        Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
            }
        }
        return out;
    }

    private boolean isLogAtBottom() {
        View child = logScroll.getChildAt(0);
        if (child == null || logScroll.getHeight() == 0) {
            return true;
        }
        return child.getBottom() - (logScroll.getHeight() + logScroll.getScrollY()) <= dp(24);
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }

    private static String message(Throwable t) {
        String text = t.getMessage();
        return text == null || text.isEmpty() ? t.getClass().getSimpleName() : text;
    }

    @Override
    protected void onDestroy() {
        // Only the log tailer is ours to stop; the detached exploit must live.
        Process tail = tailProcess;
        if (tail != null) {
            try {
                if (tail.isAlive()) {
                    tail.destroy();
                }
            } catch (Throwable ignored) {
            }
            tailProcess = null;
        }
        executor.shutdownNow();
        super.onDestroy();
    }
}
