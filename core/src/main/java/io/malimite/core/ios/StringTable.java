package io.malimite.core.ios;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** C-string literals (the {@code __cstring}-style sections) keyed by their vm address, for ingest and for the lifter. */
final class StringTable {

    record Entry(long addr, String value, String section) {}

    static final int MIN_LEN = 5;
    /** Runs in sections that mix text and data must be longer, so a few printable bytes of a table do not pass as a string. */
    static final int MIN_LEN_MIXED = 6;
    static final int MAX_LEN = 2_000;
    static final int MAX_STRINGS = 500_000;

    private StringTable() {}

    private static boolean printable(byte[] b) {
        for (byte c : b) if (c < 0x20 && c != '\t' && c != '\n' || c == 0x7f) return false;
        return true;
    }

    /** Unique string literals in file order, capped at {@link #MAX_STRINGS}. */
    static List<Entry> extract(MachOImage img) {
        List<Entry> out = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        for (MachOImage.Section s : img.sections) {
            // Ghidra also defines strings in these: Swift field names, and C strings the compiler left in __const
            // (paths, URLs, keys). Only fully printable runs are taken from them.
            boolean mixed = s.name().equals("__const") || s.name().equals("__swift5_reflstr");
            if ((s.type() != MachOImage.S_CSTRING_LITERALS && !mixed) || s.name().equals("__objc_methtype")) continue;
            int minLen = mixed ? MIN_LEN_MIXED : MIN_LEN;
            long start = s.offset(), end = start + s.size();
            long runStart = start;
            for (long p = start; p <= end && out.size() < MAX_STRINGS; p++) {
                boolean boundary = p == end || img.buf.get((int) p) == 0;
                if (!boundary) continue;
                int len = (int) (p - runStart);
                if (len >= minLen) {
                    byte[] b = new byte[Math.min(len, MAX_LEN)];
                    img.buf.get((int) runStart, b);
                    String v = new String(b, StandardCharsets.UTF_8);
                    if ((!mixed || printable(b)) && seen.add(v)) out.add(new Entry(s.addr() + (runStart - start), v, s.name()));
                }
                runStart = p + 1;
            }
        }
        return out;
    }
}
