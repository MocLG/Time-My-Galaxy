package dev.lukag.timemygalaxy;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.SharedPreferences;
import android.content.res.Configuration;
import android.graphics.Insets;
import android.graphics.Typeface;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.InputType;
import android.text.Spannable;
import android.text.SpannableStringBuilder;
import android.text.method.ScrollingMovementMethod;
import android.text.style.ForegroundColorSpan;
import android.text.style.StyleSpan;
import android.text.style.UnderlineSpan;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowInsets;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.io.IOException;
import java.io.InputStream;
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
public class MainActivity extends Activity implements PayloadStore.Log {

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
    private static final String LOAD_LOG = PayloadStore.REMOTE_DIR + "/wr_load.log";
    private static final String EXEC_LOG = PayloadStore.REMOTE_DIR + "/wr_exec.log";
    private static final String RUN_LOG = PayloadStore.REMOTE_DIR + "/run.log";

    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final Handler ui = new Handler(Looper.getMainLooper());
    private final AtomicBoolean busy = new AtomicBoolean();
    private final StringBuilder logBuffer = new StringBuilder();

    private TextView statusView;
    private TextView gateView;
    private TextView logView;
    private ScrollView logScroll;
    private boolean followLogs = true;
    private Button grantButton;
    private Button stageButton;
    private Button runButton;
    private Button stopButton;
    private Button checkButton;
    private Button commandButton;
    private EditText commandInput;
    private CheckBox darkCheck;
    private volatile Process tailProcess;
    private volatile String exploitPid;
    private volatile Targets.Target target;
    private volatile String payloadError;
    private DeviceGate.Result gateResult;

    private volatile boolean ksuReady;
    private boolean darkTheme;
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
        setTheme(darkTheme ? android.R.style.Theme_Material
                : android.R.style.Theme_Material_Light);
        super.onCreate(savedInstanceState);
        setContentView(buildUi());

        gateResult = DeviceGate.check(null);
        target = null;
        gateView.setText(gateResult.detail);
        appendLog("Time-My-Galaxy\n");
        appendLog("Transport: Shizuku shell (uid 2000)\n\n");
        refreshStatus();
        resolvePayload(this::initialResolved);
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
                    && PayloadStore.isStaged(current.dir, current.build);
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
                appendLog("[-] payload setup failed: " + t.getMessage() + "\n");
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
        gateView.setText(gateResult.detail);
        refreshStatus();
    }

    private View buildUi() {
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        final int pad = dp(16);
        root.setPadding(pad, pad, pad, pad);
        root.setOnApplyWindowInsetsListener((view, insets) -> {
            Insets bars = insets.getInsets(
                    WindowInsets.Type.systemBars() | WindowInsets.Type.displayCutout());
            view.setPadding(pad + bars.left, pad + bars.top, pad + bars.right, pad + bars.bottom);
            return insets;
        });

        TextView title = new TextView(this);
        title.setText("Time-My-Galaxy");
        title.setTextSize(22);
        title.setTypeface(Typeface.DEFAULT_BOLD);
        title.setTextColor(accentColor());
        root.addView(title);

        statusView = new TextView(this);
        statusView.setTextSize(14);
        statusView.setPadding(0, dp(8), 0, dp(4));
        statusView.setTextColor(accentColor());
        root.addView(statusView);

        gateView = new TextView(this);
        gateView.setTextSize(12);
        gateView.setTypeface(Typeface.MONOSPACE);
        gateView.setPadding(0, 0, 0, dp(8));
        root.addView(gateView);

        LinearLayout row1 = new LinearLayout(this);
        row1.setOrientation(LinearLayout.HORIZONTAL);
        grantButton = button("Grant Shizuku");
        grantButton.setOnClickListener(v -> requestShizuku());
        stageButton = button("Refetch payload");
        stageButton.setOnClickListener(v -> refetchPayload());
        row1.addView(grantButton, weight());
        row1.addView(stageButton, weight());
        root.addView(row1);

        LinearLayout row2 = new LinearLayout(this);
        row2.setOrientation(LinearLayout.HORIZONTAL);
        runButton = button("Run exploit");
        runButton.setOnClickListener(v -> confirmRun());
        stopButton = button("Restart SystemUI");
        stopButton.setOnClickListener(v -> confirmRestartSystemUi());
        row2.addView(runButton, weight());
        row2.addView(stopButton, weight());
        root.addView(row2);

        darkCheck = new CheckBox(this);
        darkCheck.setText("Dark mode");
        darkCheck.setTextSize(12);
        darkCheck.setChecked(isDarkEnabled());
        darkCheck.setOnCheckedChangeListener((buttonView, checked) -> {
            getSharedPreferences(UI_PREFS, MODE_PRIVATE).edit()
                    .putBoolean(PREF_DARK, checked).apply();
            recreate();
        });
        root.addView(darkCheck);

        TextView rootLabel = new TextView(this);
        rootLabel.setText("Root command (after the helper reports done)");
        rootLabel.setTextSize(14);
        rootLabel.setPadding(0, dp(8), 0, 0);
        rootLabel.setTextColor(accentColor());
        root.addView(rootLabel);

        commandInput = new EditText(this);
        commandInput.setHint("id");
        commandInput.setText("id");
        commandInput.setSingleLine(true);
        commandInput.setInputType(InputType.TYPE_CLASS_TEXT);
        root.addView(commandInput);

        LinearLayout row3 = new LinearLayout(this);
        row3.setOrientation(LinearLayout.HORIZONTAL);
        commandButton = button("Run as root");
        commandButton.setOnClickListener(v -> runRootCommand());
        checkButton = button("Check root");
        checkButton.setOnClickListener(v -> {
            commandInput.setText("id");
            runRootCommand();
        });
        row3.addView(commandButton, weight());
        row3.addView(checkButton, weight());
        root.addView(row3);

        logScroll = new ScrollView(this);
        LinearLayout.LayoutParams scrollParams =
                new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f);
        scrollParams.topMargin = dp(8);
        logScroll.setLayoutParams(scrollParams);
        logScroll.setOnScrollChangeListener((view, scrollX, scrollY, oldScrollX, oldScrollY) ->
                followLogs = isLogAtBottom());

        logView = new TextView(this);
        logView.setTextSize(11);
        logView.setTextColor(ansiDefaultColor);
        logView.setTypeface(Typeface.MONOSPACE);
        logView.setTextIsSelectable(true);
        logView.setMovementMethod(new ScrollingMovementMethod());
        logView.setPadding(dp(8), dp(8), dp(8), dp(8));
        logScroll.addView(logView, new ScrollView.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        root.addView(logScroll);

        return root;
    }

    private Button button(String text) {
        Button button = new Button(this);
        button.setText(text);
        return button;
    }

    private LinearLayout.LayoutParams weight() {
        LinearLayout.LayoutParams params =
                new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        params.setMarginStart(dp(4));
        params.setMarginEnd(dp(4));
        return params;
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }

    private void refreshStatus() {
        boolean running = ShizukuBridge.isRunning();
        boolean granted = running && ShizukuBridge.isGranted();
        statusView.setText("Shizuku: " + (running
                ? (granted ? "running, granted" : "running, permission needed")
                : "not running")
                + "   |   Target: " + (target == null ? "no payload" : target.build)
                + "   |   Root: " + (ksuReady ? "KernelSU" : "not loaded"));
        grantButton.setEnabled(!busy.get());
        // The handlers resolve the payload on demand, so leave stage and run
        // enabled when the last fetch failed and let the user retry.
        stageButton.setEnabled(!busy.get() && granted);
        runButton.setEnabled(!busy.get() && granted);
        stopButton.setEnabled(!busy.get() && granted);
        commandButton.setEnabled(!busy.get() && granted);
        checkButton.setEnabled(!busy.get() && granted);
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

    private void requestShizuku() {
        if (!ShizukuBridge.isRunning()) {
            new AlertDialog.Builder(this)
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
        ShizukuBridge.requestPermission(REQUEST_SHIZUKU, (granted, error) -> runOnUiThread(() -> {
            appendLog(granted ? "[+] Shizuku permission granted\n"
                    : "[-] " + (error == null ? "Shizuku permission denied" : error) + "\n");
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
                new AlertDialog.Builder(this)
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
                PayloadStore.stageAll(current.dir, current.build, this);
                appendLog("[+] staging complete\n");
            } catch (Throwable t) {
                appendLog("[-] staging failed: " + t.getMessage() + "\n");
            } finally {
                setBusy(false);
            }
        });
    }

    private void confirmRun() {
        if (busy.get()) {
            return;
        }
        resolvePayload(() -> {
            Targets.Target current = target;
            if (current == null || current.dir == null) {
                showPayloadUnavailableDialog();
                return;
            }
            String untested = current.verified ? "" : "\n\n"
                    + "WARNING: payload " + current.build + " is NOT verified on this "
                    + "firmware. An untested build can panic the kernel.";
            new AlertDialog.Builder(this)
                    .setTitle(current.verified ? "Run the exploit?" : "Run the UNTESTED exploit?")
                    .setMessage("Target " + current.build + " (" + current.describe() + ").\n\n"
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
        executor.execute(() -> {
            setBusy(true);
            Process tail = null;
            try {
                Targets.Target current = target;
                if (current == null || current.dir == null) {
                    appendLog("[-] no payload for this firmware\n");
                    return;
                }
                appendLog("[*] staging payload " + current.build + " before running\n");
                PayloadStore.stageAll(current.dir, current.build, this);

                String parked = readPidOrNull();
                if (parked == null) {
                    appendLog("[-] lost Shizuku before planting\n");
                    return;
                }
                if (!parked.isEmpty()) {
                    appendLog("[-] wr_timerfd already running: pid " + parked + "\n");
                    appendLog("[i] a planted run is cleaned only by reboot\n");
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
                    return;
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
                    appendLog("[!] live log unavailable: " + t.getMessage() + "\n");
                }

                long startedAt = System.currentTimeMillis();
                String logTail = "";
                boolean done = false;
                boolean alive = true;
                boolean lost = false;
                long lastPidCheck = 0;
                while (true) {
                    logTail = captureShell("tail -c 4096 " + quote(LOAD_LOG)
                            + " 2>/dev/null", 8000L);
                    if (!logTail.startsWith("error:") && logTail.contains("done")) {
                        done = true;
                        break;
                    }
                    if (System.currentTimeMillis() - startedAt > SUPERVISE_MS) {
                        break;
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

                long elapsed = (System.currentTimeMillis() - startedAt) / 1000;
                if (!done) {
                    logTail = captureShell("tail -c 4096 " + quote(LOAD_LOG)
                            + " 2>/dev/null", 8000L);
                    done = !logTail.startsWith("error:") && logTail.contains("done");
                }

                if (done) {
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
                } else if (!alive) {
                    appendLog("[-] wr_timerfd disappeared before done after "
                            + elapsed + "s\n");
                    if (!logTail.trim().isEmpty() && !logTail.startsWith("error:")) {
                        appendLog("[i] helper log tail:\n" + logTail.trim() + "\n");
                    }
                    appendLog("[i] reboot before trying again\n");
                } else if (lost) {
                    appendLog("[!] lost Shizuku for " + elapsed
                            + "s; the exploit is detached and may still be running\n");
                    appendLog("[i] do not replant; reboot if you want to retry\n");
                } else {
                    appendLog("[!] no done after " + elapsed + "s; exploit still running\n");
                    appendLog("[i] leave it parked and reboot when you want to retry\n");
                    if (!logTail.trim().isEmpty() && !logTail.startsWith("error:")) {
                        appendLog("[i] helper log tail:\n" + logTail.trim() + "\n");
                    }
                }
            } catch (Throwable t) {
                appendLog("[-] run failed: " + t.getMessage() + "\n");
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
                setBusy(false);
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
        new AlertDialog.Builder(this)
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
                    ui.post(() -> new AlertDialog.Builder(this)
                            .setTitle("Root required")
                            .setMessage("Restarting SystemUI only works with root, and su did "
                                    + "not return uid=0 on this boot.\n\n"
                                    + "Run the exploit first and confirm root with "
                                    + "\"Check root\".")
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
                appendLog("[-] restart failed: " + t.getMessage() + "\n");
            } finally {
                setBusy(false);
                ui.post(this::refreshStatus);
            }
        });
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
        executor.execute(() -> {
            setBusy(true);
            try {
                appendLog("$ su -c " + finalCommand + "\n");
                String out = captureShell("su -c " + ShizukuBridge.shellQuote(finalCommand),
                        20000L);
                appendLog(out.endsWith("\n") || out.isEmpty() ? out : out + "\n");
                if (out.contains("uid=0")) {
                    ksuReady = true;
                    ui.post(this::refreshStatus);
                }
            } finally {
                setBusy(false);
            }
        });
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

    /** Runs a shell command through Shizuku with a timeout, merging stdout/stderr. */
    private String captureShell(String command, long timeoutMs) {
        Process process = null;
        StringBuilder out = new StringBuilder();
        try {
            process = ShizukuBridge.exec(new String[]{"/system/bin/sh", "-c", command},
                    null, PayloadStore.REMOTE_DIR);
            final Process proc = process;
            Thread stdout = drain(proc.getInputStream(), out);
            Thread stderr = drain(proc.getErrorStream(), out);
            // RemoteProcess.exitValue() is not an IllegalThreadStateException,
            // so Process.waitFor(timeout) cannot be used here.
            long deadline = System.currentTimeMillis() + timeoutMs;
            while (process.isAlive() && System.currentTimeMillis() < deadline) {
                Thread.sleep(50);
            }
            boolean timedOut = process.isAlive();
            if (timedOut) {
                appendLog("[!] command timed out after " + timeoutMs / 1000 + "s\n");
                process.destroy();
            }
            stdout.join(1500);
            stderr.join(1500);
            synchronized (out) {
                if (!timedOut && !ShizukuBridge.isRunning()) {
                    return "error: shizuku unavailable";
                }
                return out.toString();
            }
        } catch (Throwable t) {
            return "error: " + t.getMessage();
        } finally {
            if (process != null && process.isAlive()) {
                process.destroy();
            }
        }
    }

    private Thread drain(InputStream stream, StringBuilder out) {
        Thread thread = new Thread(() -> {
            byte[] buffer = new byte[4096];
            try {
                int read;
                while ((read = stream.read(buffer)) > 0) {
                    synchronized (out) {
                        out.append(new String(buffer, 0, read));
                    }
                }
            } catch (IOException ignored) {
            }
        }, "capture");
        thread.setDaemon(true);
        thread.start();
        return thread;
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
        new AlertDialog.Builder(this)
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
            boolean follow = followLogs;
            logBuffer.append(text);
            if (logBuffer.length() > LOG_LIMIT) {
                logBuffer.delete(0, logBuffer.length() - LOG_LIMIT / 2);
                logBuffer.insert(0, "[... earlier output dropped ...]\n");
            }
            logView.setText(renderLog());
            if (follow) {
                logScroll.post(() -> logScroll.scrollTo(0, logView.getBottom()));
            }
        });
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

    private int accentColor() {
        return darkTheme ? 0xFF6BE86B : 0xFF0A6B0A;
    }

    private boolean isLogAtBottom() {
        View child = logScroll.getChildAt(0);
        if (child == null || logScroll.getHeight() == 0) {
            return true;
        }
        return child.getBottom() - (logScroll.getHeight() + logScroll.getScrollY()) <= dp(24);
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
