package dev.lukag.timemygalaxy;

import java.util.ArrayList;
import java.util.List;

/**
 * One root shell script, split by markers, that reports the state after a run.
 * Checks are informational only and never gate anything.
 */
final class RunChecks {

    static final class Row {
        final boolean ok;
        final String label;
        final String detail;

        Row(boolean ok, String label, String detail) {
            this.ok = ok;
            this.label = label;
            this.detail = detail == null ? "" : detail;
        }
    }

    static final class Result {
        final List<Row> rows;

        Result(List<Row> rows) {
            this.rows = rows;
        }

        boolean root() {
            return !rows.isEmpty() && rows.get(0).ok;
        }

        String text() {
            StringBuilder out = new StringBuilder();
            for (Row row : rows) {
                out.append(row.ok ? "[+] " : "[!] ").append(row.label);
                if (!row.detail.isEmpty()) {
                    out.append(": ").append(row.detail);
                }
                out.append('\n');
            }
            return out.toString().trim();
        }

        String oneLine() {
            StringBuilder out = new StringBuilder();
            for (Row row : rows) {
                if (out.length() > 0) {
                    out.append(" | ");
                }
                out.append(row.ok ? "+" : "!").append(' ').append(row.label);
                if (!row.detail.isEmpty()) {
                    out.append(' ').append(row.detail);
                }
            }
            return out.toString();
        }
    }

    private static final String MARKER = "__tmg_sep_";

    private RunChecks() {
    }

    static Result run(Provider provider, Shell.Log log) {
        String code = String.valueOf(provider.versionCode);
        String script = "id 2>&1"
                + "; echo " + MARKER + "1"
                + "; /data/local/tmp/wr/ksud --version 2>&1"
                + "; echo " + MARKER + "2"
                + "; ls /data/adb/modules 2>&1"
                + "; echo " + MARKER + "3"
                + "; pm list packages --show-versioncode " + provider.packageName + " 2>&1";
        String out = Shell.root(script, 40_000L, log);
        String[] parts = out.split("__tmg_sep_[0-9]", 4);

        String id = part(parts, 0);
        String ksud = part(parts, 1);
        String modules = part(parts, 2);
        String manager = part(parts, 3);

        List<Row> rows = new ArrayList<>();
        boolean root = id.contains("uid=0");
        rows.add(new Row(root, "root", root ? firstLine(id) : "su did not return uid=0"));

        boolean ksudOk = ksud.contains(provider.ksudVersionToken) || ksud.contains(code);
        rows.add(new Row(ksudOk, "ksud (" + provider.label + ")", firstLine(ksud)));

        String moduleList = modules.trim().replaceAll("\\s+", ", ");
        if (moduleList.length() > 120) {
            moduleList = moduleList.substring(0, 120) + "...";
        }
        rows.add(new Row(!moduleList.isEmpty() && !moduleList.startsWith("ls: "),
                "modules", moduleList.isEmpty() ? "none" : moduleList));

        boolean managerOk = manager.contains("versionCode:" + code)
                || manager.contains("versionCode=" + code);
        rows.add(new Row(managerOk, "manager", firstLine(manager)));

        return new Result(rows);
    }

    private static String part(String[] parts, int index) {
        return index < parts.length ? parts[index].trim() : "";
    }

    private static String firstLine(String value) {
        String text = value == null ? "" : value.trim();
        int newline = text.indexOf('\n');
        if (newline >= 0) {
            text = text.substring(0, newline).trim();
        }
        return text.length() > 160 ? text.substring(0, 160) + "..." : text;
    }

}
