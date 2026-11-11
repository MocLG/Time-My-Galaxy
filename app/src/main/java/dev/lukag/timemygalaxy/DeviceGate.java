package dev.lukag.timemygalaxy;

import android.os.Build;

import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Reads the running firmware's Samsung PDA string.
 *
 * /proc/version is not readable by app UIDs, so use Build.VERSION.INCREMENTAL
 * and the other identity strings, which carry the Samsung PDA.
 */
final class DeviceGate {

    /**
     * S731BXXU9CZIF and friends: one letter, three digits, then the rest of
     * the PDA. The lookarounds keep it from matching inside a longer token
     * such as the fingerprint's product name.
     */
    private static final Pattern BUILD_ID =
            Pattern.compile("(?<![A-Z0-9])([A-Z][0-9]{3}[A-Z0-9]{6,12})(?![A-Z0-9])");

    static final class Result {
        final Targets.Target target;
        final String detail;

        Result(Targets.Target target, String detail) {
            this.target = target;
            this.detail = detail;
        }
    }

    private DeviceGate() {
    }

    static String buildId() {
        String[] identity = {
                Build.VERSION.INCREMENTAL, Build.DISPLAY, Build.FINGERPRINT, Build.ID
        };
        for (String value : identity) {
            if (value == null) {
                continue;
            }
            Matcher matcher = BUILD_ID.matcher(value.toUpperCase(Locale.US));
            if (matcher.find()) {
                return matcher.group(1);
            }
        }
        return null;
    }

    static Result check(Targets.Target target) {
        String model = safe(Build.MODEL);
        String fingerprint = safe(Build.FINGERPRINT);
        String incremental = safe(Build.VERSION.INCREMENTAL);
        String build = buildId();
        String kernel = System.getProperty("os.version", "unknown");

        StringBuilder detail = new StringBuilder();
        detail.append("[+] model ").append(model).append('\n');
        if (target == null) {
            detail.append("[-] no payload loaded for build ")
                    .append(build == null ? "unknown" : build).append('\n');
            detail.append("    incremental ").append(incremental).append('\n');
            detail.append("    fingerprint ").append(fingerprint).append('\n');
            detail.append("[i] connect to the internet to download it");
        } else {
            detail.append(target.verified ? "[+] firmware " : "[!] firmware ")
                    .append(target.build).append(target.verified
                            ? " (verified)" : " (untested)")
                    .append('\n');
            detail.append("[i] payload ").append(target.build).append(", ")
                    .append(target.describe()).append('\n');
            if (!model.equalsIgnoreCase(target.model)) {
                detail.append("[!] model does not match manifest (expected ")
                        .append(target.model).append(")\n");
            }
            detail.append("[i] kernel ").append(kernel);
        }
        return new Result(target, detail.toString());
    }

    private static String safe(String value) {
        return value == null ? "unknown" : value;
    }
}
