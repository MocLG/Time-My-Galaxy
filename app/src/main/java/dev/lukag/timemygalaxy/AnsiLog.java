package dev.lukag.timemygalaxy;

import java.util.ArrayList;
import java.util.List;

/**
 * Turns ANSI SGR output (the colours the exploit binary prints) into text runs
 * the log view can paint. Kept free of Android types so it can be unit-tested
 * on a plain JVM.
 *
 * Colours are theme-aware: "white" becomes the theme foreground, and anything
 * that would vanish against the background (pure black on a dark log, near-white
 * on a light one) is nudged toward the opposite end while keeping its hue.
 */
final class AnsiLog {

    static final class Run {
        final String text;
        final int color;
        final boolean bold;
        final boolean italic;
        final boolean underline;

        Run(String text, int color, boolean bold, boolean italic, boolean underline) {
            this.text = text;
            this.color = color;
            this.bold = bold;
            this.italic = italic;
            this.underline = underline;
        }
    }

    /** 0-7: black, red, green, yellow, blue, magenta, cyan, white. */
    private static final int[] DARK = {
            0xFF8A8A8A, 0xFFFF5555, 0xFF4BE34B, 0xFFE8E337,
            0xFF6A8DFF, 0xFFFF6BE8, 0xFF4BE3E3, 0xFFFFFFFF,
    };
    private static final int[] DARK_BRIGHT = {
            0xFFA8A8A8, 0xFFFF8A8A, 0xFF8CFF8C, 0xFFFFFF8A,
            0xFF9AB0FF, 0xFFFF9AEF, 0xFF9AFFFF, 0xFFFFFFFF,
    };
    private static final int[] LIGHT = {
            0xFF000000, 0xFFB00000, 0xFF006600, 0xFF7A5C00,
            0xFF0000A8, 0xFF960096, 0xFF006666, 0xFF000000,
    };
    private static final int[] LIGHT_BRIGHT = {
            0xFF333333, 0xFFC20000, 0xFF007A00, 0xFF8A6A00,
            0xFF0000C8, 0xFFA800A8, 0xFF007878, 0xFF000000,
    };

    private AnsiLog() {
    }

    static List<Run> parse(CharSequence raw, int defaultColor, boolean dark) {
        List<Run> runs = new ArrayList<>();
        StringBuilder pending = new StringBuilder();
        int fg = defaultColor;
        boolean bold = false;
        boolean italic = false;
        boolean underline = false;
        int n = raw.length();
        int i = 0;

        while (i < n) {
            char c = raw.charAt(i);
            if (c == 0x1b && i + 1 < n && raw.charAt(i + 1) == '[') {
                int j = i + 2;
                while (j < n && !isFinalByte(raw.charAt(j))) {
                    j++;
                }
                if (j >= n) {
                    break; // incomplete escape: drop the tail
                }
                if (raw.charAt(j) == 'm') {
                    flush(runs, pending, fg, bold, italic, underline);
                    int[] codes = params(raw.subSequence(i + 2, j).toString());
                    for (int k = 0; k < codes.length; k++) {
                        int code = codes[k];
                        if (code == 0) {
                            fg = defaultColor;
                            bold = italic = underline = false;
                        } else if (code == 1) {
                            bold = true;
                        } else if (code == 3) {
                            italic = true;
                        } else if (code == 4) {
                            underline = true;
                        } else if (code == 22) {
                            bold = false;
                        } else if (code == 23) {
                            italic = false;
                        } else if (code == 24) {
                            underline = false;
                        } else if (code == 39) {
                            fg = defaultColor;
                        } else if (code >= 30 && code <= 37) {
                            fg = ansi(code - 30, false, defaultColor, dark);
                        } else if (code >= 90 && code <= 97) {
                            fg = ansi(code - 90, true, defaultColor, dark);
                        } else if (code == 38 && k + 1 < codes.length) {
                            if (codes[k + 1] == 5 && k + 2 < codes.length) {
                                fg = fit(xterm(codes[k + 2], defaultColor, dark), dark);
                                k += 2;
                            } else if (codes[k + 1] == 2 && k + 4 < codes.length) {
                                fg = fit(0xFF000000
                                        | (clamp(codes[k + 2]) << 16)
                                        | (clamp(codes[k + 3]) << 8)
                                        | clamp(codes[k + 4]), dark);
                                k += 4;
                            }
                        }
                        // Background colours and other SGR attributes are ignored.
                    }
                }
                i = j + 1;
                continue;
            }
            pending.append(c);
            i++;
        }
        flush(runs, pending, fg, bold, italic, underline);
        return runs;
    }

    private static void flush(List<Run> runs, StringBuilder pending,
                              int fg, boolean bold, boolean italic, boolean underline) {
        if (pending.length() == 0) {
            return;
        }
        runs.add(new Run(pending.toString(), fg, bold, italic, underline));
        pending.setLength(0);
    }

    private static boolean isFinalByte(char c) {
        return c >= 0x40 && c <= 0x7e;
    }

    private static int[] params(String body) {
        if (body.isEmpty()) {
            return new int[]{0};
        }
        String[] parts = body.split(";", -1);
        int[] out = new int[parts.length];
        for (int i = 0; i < parts.length; i++) {
            try {
                out[i] = parts[i].isEmpty() ? 0 : Integer.parseInt(parts[i].trim());
            } catch (NumberFormatException e) {
                out[i] = -1;
            }
        }
        return out;
    }

    private static int ansi(int index, boolean bright, int defaultColor, boolean dark) {
        if (index == 7) {
            return defaultColor; // "white" means the theme foreground
        }
        int[] table = dark
                ? (bright ? DARK_BRIGHT : DARK)
                : (bright ? LIGHT_BRIGHT : LIGHT);
        return table[index];
    }

    private static int xterm(int index, int defaultColor, boolean dark) {
        if (index < 0) {
            return defaultColor;
        }
        if (index < 16) {
            return ansi(index % 8, index >= 8, defaultColor, dark);
        }
        if (index < 232) {
            int v = index - 16;
            int[] level = {0, 95, 135, 175, 215, 255};
            int r = level[v / 36];
            int g = level[(v % 36) / 6];
            int b = level[v % 6];
            return 0xFF000000 | (r << 16) | (g << 8) | b;
        }
        int gray = 8 + (Math.min(index, 255) - 232) * 10;
        return 0xFF000000 | (gray << 16) | (gray << 8) | gray;
    }

    /** Keeps an arbitrary RGB colour legible on the current log background. */
    private static int fit(int color, boolean dark) {
        double lum = luminance(color);
        if (dark) {
            if (lum < 0.18) {
                return blend(color, 0xFFFFFFFF, 0.55);
            }
        } else if (lum > 0.55) {
            return blend(color, 0xFF000000, 0.55);
        }
        return color;
    }

    private static double luminance(int color) {
        return 0.2126 * channel((color >> 16) & 0xFF)
                + 0.7152 * channel((color >> 8) & 0xFF)
                + 0.0722 * channel(color & 0xFF);
    }

    private static double channel(int value) {
        double c = value / 255.0;
        return c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4);
    }

    private static int blend(int a, int b, double factor) {
        int ar = (a >> 16) & 0xFF;
        int ag = (a >> 8) & 0xFF;
        int ab = a & 0xFF;
        int br = (b >> 16) & 0xFF;
        int bg = (b >> 8) & 0xFF;
        int bb = b & 0xFF;
        int r = (int) Math.round(ar + (br - ar) * factor);
        int g = (int) Math.round(ag + (bg - ag) * factor);
        int bl = (int) Math.round(ab + (bb - ab) * factor);
        return 0xFF000000 | (r << 16) | (g << 8) | bl;
    }

    private static int clamp(int value) {
        return Math.max(0, Math.min(255, value));
    }
}
