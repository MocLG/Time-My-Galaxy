package dev.lukag.timemygalaxy;

import java.io.File;

/**
 * One firmware build's payload metadata, taken from the signed manifest that
 * describes the installed bundle.
 *
 * Nothing is bundled in the APK. profile.json still carries the porter's
 * model, SoC and Android fields, but the trusted copy of the verified flag and
 * of the file hashes lives in the signed manifest.
 */
final class Targets {

    static final class Target {
        final String build;
        final String model;
        final String soc;
        final String android;
        final boolean verified;
        final int rev;
        final File dir;

        Target(String build, String model, String soc, String android, boolean verified,
                int rev, File dir) {
            this.build = build;
            this.model = model == null || model.isEmpty() ? "unknown" : model;
            this.soc = soc;
            this.android = android;
            this.verified = verified;
            this.rev = rev;
            this.dir = dir;
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
            if (!verified) {
                out.append(", untested");
            }
            return out.toString();
        }
    }

    private Targets() {
    }
}
