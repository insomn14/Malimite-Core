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
    static final int MAX_LEN = 2_000;
    static final int MAX_STRINGS = 500_000;

    private StringTable() {}

    /** Unique string literals in file order, capped at {@link #MAX_STRINGS}. */
    static List<Entry> extract(MachOImage img) {
        List<Entry> out = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        for (MachOImage.Section s : img.sections) {
            if (s.type() != MachOImage.S_CSTRING_LITERALS || s.name().equals("__objc_methtype")) continue;
            long start = s.offset(), end = start + s.size();
            long runStart = start;
            for (long p = start; p <= end && out.size() < MAX_STRINGS; p++) {
                boolean boundary = p == end || img.buf.get((int) p) == 0;
                if (!boundary) continue;
                int len = (int) (p - runStart);
                if (len >= MIN_LEN) {
                    byte[] b = new byte[Math.min(len, MAX_LEN)];
                    img.buf.get((int) runStart, b);
                    String v = new String(b, StandardCharsets.UTF_8);
                    if (seen.add(v)) out.add(new Entry(s.addr() + (runStart - start), v, s.name()));
                }
                runStart = p + 1;
            }
        }
        return out;
    }
}
