package dev.lukag.timemygalaxy;

import android.content.res.AssetManager;
import android.os.Build;

/**
 * Matches the running firmware against the payloads bundled in the APK.
 *
 * /proc/version is not readable by app UIDs, so use Build.FINGERPRINT and
 * Build.VERSION.INCREMENTAL, which carry the Samsung PDA string.
 */
final class DeviceGate {

    static final class Result {
        final Targets.Target target;
        final boolean matches;
        final boolean verified;
        final String model;
        final String fingerprint;
        final String incremental;
        final String kernel;
        final String detail;

        Result(Targets.Target target, String model, String fingerprint, String incremental,
                String kernel, String detail) {
            this.target = target;
            this.matches = target != null;
            this.verified = target != null && target.verified;
            this.model = model;
            this.fingerprint = fingerprint;
            this.incremental = incremental;
            this.kernel = kernel;
            this.detail = detail;
        }
    }

    private DeviceGate() {
    }

    static Result check(AssetManager assets) {
        String model = safe(Build.MODEL);
        String fingerprint = safe(Build.FINGERPRINT);
        String incremental = safe(Build.VERSION.INCREMENTAL);
        String display = safe(Build.DISPLAY);
        String id = safe(Build.ID);
        String kernel = System.getProperty("os.version", "unknown");

        Targets.Target target = Targets.detect(assets, fingerprint, incremental, display, id);

        StringBuilder detail = new StringBuilder();
        detail.append("[+] model ").append(model).append('\n');
        if (target == null) {
            detail.append("[-] no payload matches this firmware\n");
            detail.append("    fingerprint ").append(fingerprint).append('\n');
            detail.append("    incremental ").append(incremental).append('\n');
            detail.append("[i] available payloads: ").append(Targets.available(assets));
        } else {
            detail.append(target.verified ? "[+] firmware " : "[!] firmware ")
                    .append(target.build).append(target.verified
                            ? " (verified)" : " (untested)")
                    .append('\n');
            detail.append("[i] payload ").append(target.build).append(", ")
                    .append(target.describe()).append('\n');
            if (!model.equalsIgnoreCase(target.model)) {
                detail.append("[!] model does not match table (expected ")
                        .append(target.model).append(")\n");
            }
            detail.append("[i] kernel ").append(kernel);
        }
        return new Result(target, model, fingerprint, incremental, kernel, detail.toString());
    }

    private static String safe(String value) {
        return value == null ? "unknown" : value;
    }
}
