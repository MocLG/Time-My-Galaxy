package dev.lukag.timemygalaxy;

import android.content.Context;
import android.content.SharedPreferences;

/**
 * Which KernelSU flavour a run uses: the daemon that is staged, the
 * late-load arguments its helper passes, and the manager that gets pinned.
 */
final class Provider {

    static final String PREF = "provider";
    static final String LEGACY_ID = "kernelsu";
    static final String NEXT_ID = "kernelsu-next";

    final String id;
    final String label;
    final String packageName;
    final long versionCode;
    final String versionName;
    final String ksudVersionToken;
    final String payloadFile;
    final String lateLoadArgs;
    final String apkName;
    final String apkUrl;
    final String apkSha256;
    final long apkBytes;

    private Provider(String id, String label, String packageName, long versionCode,
            String versionName, String ksudVersionToken, String payloadFile,
            String lateLoadArgs, String apkName, String apkUrl, String apkSha256,
            long apkBytes) {
        this.id = id;
        this.label = label;
        this.packageName = packageName;
        this.versionCode = versionCode;
        this.versionName = versionName;
        this.ksudVersionToken = ksudVersionToken;
        this.payloadFile = payloadFile;
        this.lateLoadArgs = lateLoadArgs;
        this.apkName = apkName;
        this.apkUrl = apkUrl;
        this.apkSha256 = apkSha256;
        this.apkBytes = apkBytes;
    }

    static final Provider LEGACY = new Provider(
            LEGACY_ID, "KernelSU", "me.weishu.kernelsu", 32525L, "v3.2.5", "3.2.5",
            "ksud", "--ephemeral --allow-shell",
            "KernelSU_v3.2.5_32525-release.apk",
            "https://github.com/tiann/KernelSU/releases/download/v3.2.5/"
                    + "KernelSU_v3.2.5_32525-release.apk",
            "1417081413bf7ab1de8e440ecbcb62685037c8f28f048f0f8b79e305b31ab916",
            9_083_665L);

    static final Provider NEXT = new Provider(
            NEXT_ID, "KernelSU-Next", "com.rifsxd.ksunext", 33355L, "v3.4.2", "3.4.2",
            "ksud-next", "--allow-shell",
            "KernelSU_Next_v3.4.2_33355-release.apk",
            "https://github.com/KernelSU-Next/KernelSU-Next/releases/download/v3.4.2/"
                    + "KernelSU_Next_v3.4.2_33355-release.apk",
            "774a5511f7034a4930e881114e202319cbdc34c5aaaa5c7c6b6d2902364e4c58",
            16_682_167L);

    static Provider of(String id) {
        return NEXT_ID.equals(id) ? NEXT : LEGACY;
    }

    static Provider selected(Context context) {
        SharedPreferences prefs = context.getSharedPreferences("wroot-ui",
                Context.MODE_PRIVATE);
        return of(prefs.getString(PREF, LEGACY_ID));
    }

    static void select(Context context, Provider provider) {
        context.getSharedPreferences("wroot-ui", Context.MODE_PRIVATE).edit()
                .putString(PREF, provider.id).apply();
    }

    boolean isNext() {
        return NEXT_ID.equals(id);
    }
}
