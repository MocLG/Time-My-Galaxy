package dev.lukag.timemygalaxy;

import android.os.ParcelFileDescriptor;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import moe.shizuku.server.IRemoteProcess;
import moe.shizuku.server.IShizukuService;
import rikka.shizuku.Shizuku;

/**
 * Minimal shell bridge over Shizuku, adapted from Root-My-Galaxy's
 * ShizukuController (Apache-2.0). Shizuku must already be running as the
 * Android shell user (uid 2000); this app never executes payloads in its
 * own sandbox.
 */
final class ShizukuBridge {

    interface PermissionCallback {
        void onResult(boolean granted, String error);
    }

    private static Shizuku.OnRequestPermissionResultListener listener;

    private ShizukuBridge() {
    }

    static boolean isRunning() {
        try {
            return Shizuku.pingBinder();
        } catch (Throwable t) {
            return false;
        }
    }

    static boolean isGranted() {
        try {
            return isRunning() && Shizuku.checkSelfPermission() == android.content.pm.PackageManager.PERMISSION_GRANTED;
        } catch (Throwable t) {
            return false;
        }
    }

    static void requestPermission(int requestCode, PermissionCallback callback) {
        if (!isRunning()) {
            callback.onResult(false, "Shizuku is not running");
            return;
        }
        if (isGranted()) {
            callback.onResult(true, null);
            return;
        }
        if (listener != null) {
            Shizuku.removeRequestPermissionResultListener(listener);
        }
        listener = (code, grantResult) -> {
            if (code != requestCode) {
                return;
            }
            Shizuku.removeRequestPermissionResultListener(listener);
            listener = null;
            callback.onResult(grantResult == android.content.pm.PackageManager.PERMISSION_GRANTED,
                    grantResult == android.content.pm.PackageManager.PERMISSION_GRANTED
                            ? null : "Shizuku permission was denied");
        };
        Shizuku.addRequestPermissionResultListener(listener);
        try {
            Shizuku.requestPermission(requestCode);
        } catch (Throwable t) {
            Shizuku.removeRequestPermissionResultListener(listener);
            listener = null;
            callback.onResult(false, t.getMessage());
        }
    }

    static Process exec(String[] cmd, String[] env, String dir) {
        if (!isRunning()) {
            throw new IllegalStateException("Shizuku is not running");
        }
        android.os.IBinder binder = Shizuku.getBinder();
        if (binder == null) {
            throw new IllegalStateException("Shizuku binder is not available");
        }
        try {
            IRemoteProcess remote = IShizukuService.Stub.asInterface(binder).newProcess(cmd, env, dir);
            if (remote == null) {
                throw new IllegalStateException("Shizuku returned no process");
            }
            return new RemoteProcess(remote);
        } catch (RuntimeException e) {
            throw e;
        } catch (Throwable t) {
            throw new IllegalStateException("Shizuku exec failed: " + t.getMessage(), t);
        }
    }

    static void writeFile(String remotePath, String mode, InputStream source) throws IOException {
        String quoted = shellQuote(remotePath);
        // Remove first: a leftover owned by root cannot be truncated by uid 2000
        // even though the directory itself is writable by shell.
        Process process = exec(new String[]{"/system/bin/sh", "-c",
                        "rm -f " + quoted + " 2>/dev/null; cat > " + quoted
                                + " && chmod " + mode + " " + quoted},
                null, "/data/local/tmp");
        StringBuilder errors = new StringBuilder();
        Thread drain = new Thread(() -> {
            byte[] buffer = new byte[4096];
            try (InputStream error = process.getErrorStream()) {
                int read;
                while ((read = error.read(buffer)) > 0) {
                    synchronized (errors) {
                        errors.append(new String(buffer, 0, read));
                    }
                }
            } catch (IOException ignored) {
            }
        }, "stage-stderr");
        drain.setDaemon(true);
        drain.start();
        int exit;
        try (OutputStream output = process.getOutputStream()) {
            try (InputStream input = source) {
                byte[] buffer = new byte[64 * 1024];
                int read;
                while ((read = input.read(buffer)) > 0) {
                    output.write(buffer, 0, read);
                }
            }
            output.flush();
        }
        try {
            exit = process.waitFor();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            process.destroy();
            throw new IOException("interrupted while staging " + remotePath);
        } finally {
            if (process.isAlive()) {
                process.destroy();
            }
        }
        if (exit != 0) {
            String detail;
            synchronized (errors) {
                detail = errors.toString().trim();
            }
            throw new IOException("staging " + remotePath + " failed (exit " + exit + ")"
                    + (detail.isEmpty() ? "" : ": " + detail));
        }
    }

    static String capture(String[] cmd, String[] env, String dir) throws IOException, InterruptedException {
        Process process = exec(cmd, env, dir);
        StringBuilder out = new StringBuilder();
        // Read each stream to EOF in its own thread. Polling available() loses
        // output from short-lived commands: the pipe can report 0 bytes while
        // data is still in flight, and the process may exit before it lands.
        Thread stdout = drainTo(process.getInputStream(), out);
        Thread stderr = drainTo(process.getErrorStream(), out);
        try {
            process.waitFor();
        } finally {
            if (process.isAlive()) {
                process.destroy();
            }
        }
        stdout.join(2000);
        stderr.join(2000);
        synchronized (out) {
            return out.toString();
        }
    }

    private static Thread drainTo(InputStream stream, StringBuilder out) {
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
        }, "shizuku-capture");
        thread.setDaemon(true);
        thread.start();
        return thread;
    }

    static String shellQuote(String value) {
        return "'" + value.replace("'", "'\\''") + "'";
    }

    private static final class RemoteProcess extends Process {
        private final IRemoteProcess remote;
        private InputStream input;
        private OutputStream output;
        private InputStream error;

        RemoteProcess(IRemoteProcess remote) {
            this.remote = remote;
        }

        @Override
        public synchronized InputStream getInputStream() {
            if (input == null) {
                try {
                    input = new ParcelFileDescriptor.AutoCloseInputStream(remote.getInputStream());
                } catch (Throwable t) {
                    throw new IllegalStateException(t);
                }
            }
            return input;
        }

        @Override
        public synchronized OutputStream getOutputStream() {
            if (output == null) {
                try {
                    output = new ParcelFileDescriptor.AutoCloseOutputStream(remote.getOutputStream());
                } catch (Throwable t) {
                    throw new IllegalStateException(t);
                }
            }
            return output;
        }

        @Override
        public synchronized InputStream getErrorStream() {
            if (error == null) {
                try {
                    error = new ParcelFileDescriptor.AutoCloseInputStream(remote.getErrorStream());
                } catch (Throwable t) {
                    throw new IllegalStateException(t);
                }
            }
            return error;
        }

        @Override
        public int waitFor() throws InterruptedException {
            try {
                return remote.waitFor();
            } catch (Throwable t) {
                throw new IllegalStateException(t);
            }
        }

        @Override
        public int exitValue() {
            try {
                return remote.exitValue();
            } catch (Throwable t) {
                throw new IllegalStateException(t);
            }
        }

        @Override
        public void destroy() {
            try {
                remote.destroy();
            } catch (Throwable ignored) {
            }
        }

        @Override
        public boolean isAlive() {
            try {
                return remote.alive();
            } catch (Throwable t) {
                return false;
            }
        }
    }
}
