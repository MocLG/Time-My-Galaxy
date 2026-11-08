package dev.lukag.timemygalaxy;

import java.util.Locale;

/**
 * Payload table. One entry: the firmware this exploit was built and verified
 * on. Assets live under assets/payload/&lt;BUILD&gt;/.
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
            this.model = model;
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
            return out.toString();
        }
    }

    private static final Target[] ALL = {
            new Target("S731BXXU9CZIF", "SM-S731B", "Exynos 2400", "17", true),
    };

    private Targets() {
    }

    static Target[] all() {
        return ALL.clone();
    }

    static int count() {
        return ALL.length;
    }

    static Target byBuild(String build) {
        if (build == null) {
            return null;
        }
        String wanted = build.trim().toUpperCase(Locale.US);
        for (Target target : ALL) {
            if (target.build.equals(wanted)) {
                return target;
            }
        }
        return null;
    }

    /**
     * Samsung puts the PDA in the fingerprint tail and in VERSION.INCREMENTAL,
     * so match it against the identity strings in order.
     */
    static Target detect(String model, String... identity) {
        if (identity == null) {
            return null;
        }
        for (String value : identity) {
            if (value == null) {
                continue;
            }
            String upper = value.toUpperCase(Locale.US);
            for (Target target : ALL) {
                if (upper.contains(target.build)) {
                    return target;
                }
            }
        }
        return null;
    }
}
