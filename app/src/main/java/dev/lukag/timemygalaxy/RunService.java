package dev.lukag.timemygalaxy;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.os.Build;
import android.os.IBinder;
import android.os.PowerManager;

import androidx.core.app.NotificationCompat;
import androidx.core.app.ServiceCompat;
import androidx.core.content.ContextCompat;

/**
 * Foreground anchor for a run so supervision continues with the screen off.
 * The run itself never depends on this service.
 */
public class RunService extends Service {

    private static final String CHANNEL = "run";
    private static final int ID = 0x5752;
    private static volatile RunService instance;

    private PowerManager.WakeLock wakeLock;
    private String build = "?";

    static void start(Context context, String build) {
        Intent intent = new Intent(context, RunService.class).putExtra("build", build);
        try {
            ContextCompat.startForegroundService(context, intent);
        } catch (Throwable ignored) {
        }
    }

    static void update(String text) {
        RunService service = instance;
        if (service != null) {
            service.notify(text);
        }
    }

    static void stop(Context context) {
        try {
            context.stopService(new Intent(context, RunService.class));
        } catch (Throwable ignored) {
        }
    }

    @Override
    public void onCreate() {
        super.onCreate();
        instance = this;
        PowerManager power = getSystemService(PowerManager.class);
        if (power != null) {
            wakeLock = power.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "TimeMyGalaxy:run");
            wakeLock.acquire(10 * 60 * 1000L);
        }
        createChannel();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null) {
            String value = intent.getStringExtra("build");
            if (value != null) {
                build = value;
            }
        }
        notify(getString(R.string.notification_supervising, build));
        return START_NOT_STICKY;
    }

    private void notify(String text) {
        Intent open = new Intent(this, MainActivity.class)
                .addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP);
        PendingIntent content = PendingIntent.getActivity(this, 0, open,
                PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
        Notification notification = new NotificationCompat.Builder(this, CHANNEL)
                .setSmallIcon(R.drawable.ic_stat_run)
                .setContentTitle(getString(R.string.app_name))
                .setContentText(text)
                .setOngoing(true)
                .setOnlyAlertOnce(true)
                .setPriority(NotificationCompat.PRIORITY_LOW)
                .setContentIntent(content)
                .build();
        try {
            ServiceCompat.startForeground(this, ID, notification,
                    Build.VERSION.SDK_INT >= 34
                            ? ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC : 0);
        } catch (Throwable ignored) {
            // The run continues even when the system refuses the anchor.
        }
    }

    private void createChannel() {
        NotificationManager manager = getSystemService(NotificationManager.class);
        if (manager == null) {
            return;
        }
        NotificationChannel channel = new NotificationChannel(CHANNEL, getString(R.string.notification_channel_name),
                NotificationManager.IMPORTANCE_LOW);
        channel.setDescription(getString(R.string.notification_channel_desc));
        manager.createNotificationChannel(channel);
    }

    @Override
    public void onDestroy() {
        instance = null;
        if (wakeLock != null && wakeLock.isHeld()) {
            wakeLock.release();
        }
        super.onDestroy();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}
