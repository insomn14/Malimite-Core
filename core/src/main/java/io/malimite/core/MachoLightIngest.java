package io.malimite.core;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Ghidra-free ingest for the iOS "light" scan: printable strings and imported symbols read straight from the
 * Mach-O, so a 100MB+ binary costs a streaming pass instead of >6GB of auto-analysis. Produces the same
 * MachoStrings / Functions rows the string, symbol-name, resource and absence rules read.
 */
final class MachoLightIngest {

    private static final Logger log = LoggerFactory.getLogger(MachoLightIngest.class);

    static final int MIN_LEN = 6;
    static final int MAX_LEN = 2_000;
    static final int MAX_STRINGS = 500_000;
    private static final int BATCH = 20_000;
    private static final int MAX_STRTAB = 256 << 20;
    private static final String IMPORTS_CLASS = "Imports";

    private MachoLightIngest() {}

    static int ingestStrings(Path macho, SqliteStore store, String executableName) throws IOException {
        Set<String> seen = new HashSet<>();
        List<String[]> batch = new ArrayList<>();
        int[] total = {0};
        StringBuilder run = new StringBuilder();
        long runStart = 0, pos = 0;
        long[] skip = symbolStringTable(macho);  // symbol names are ingested as imports, not as noisy strings
        byte[] buf = new byte[1 << 20];
        try (InputStream in = Files.newInputStream(macho)) {
            int n;
            while ((n = in.read(buf)) > 0 && total[0] < MAX_STRINGS) {
                for (int i = 0; i < n; i++, pos++) {
                    int b = buf[i] & 0xff;
                    if (pos >= skip[0] && pos < skip[1]) b = 0;
                    if ((b >= 0x20 && b < 0x7f) || b == '\t') {
                        if (run.length() == 0) runStart = pos;
                        if (run.length() < MAX_LEN) run.append((char) b);
                    } else if (run.length() > 0) {
                        flushRun(run, runStart, seen, batch, total, store, executableName);
                    }
                }
            }
            if (run.length() > 0) flushRun(run, runStart, seen, batch, total, store, executableName);
        }
        if (!batch.isEmpty()) store.insertMachoStrings(batch, executableName);
        if (total[0] >= MAX_STRINGS) log.warn("Light ingest hit the {} string cap: strings late in the file were not scanned", MAX_STRINGS);
        log.info("Light ingest: {} unique strings from {}", total[0], macho.getFileName());
        return total[0];
    }

    private static void flushRun(StringBuilder run, long start, Set<String> seen, List<String[]> batch,
                                 int[] total, SqliteStore store, String exec) {
        if (run.length() >= MIN_LEN && total[0] < MAX_STRINGS) {
            String s = run.toString();
            if (seen.add(s)) {
                batch.add(new String[] {"0x" + Long.toHexString(start), s, "raw", ""});
                total[0]++;
                if (batch.size() >= BATCH) {
                    store.insertMachoStrings(batch, exec);
                    batch.clear();
                }
            }
        }
        run.setLength(0);
    }

    /** Undefined external symbols (what the app imports: libc calls, ObjC class refs). Returns the row count. */
    static int ingestImports(Path macho, SqliteStore store, String executableName) throws IOException {
        List<SqliteStore.DecompilationResult> rows = new ArrayList<>();
        try (FileChannel ch = FileChannel.open(macho, StandardOpenOption.READ)) {
            long base = sliceOffset(ch);
            ByteBuffer hdr = read(ch, base, 32, ByteOrder.LITTLE_ENDIAN);
            if (hdr.getInt(0) != 0xFEEDFACF) {
                log.warn("Light ingest: not a 64-bit little-endian Mach-O, skipping symbol imports");
                return 0;
            }
            int ncmds = hdr.getInt(16);
            long cmdOff = base + 32;
            for (int c = 0; c < ncmds; c++) {
                ByteBuffer lc = read(ch, cmdOff, 24, ByteOrder.LITTLE_ENDIAN);
                int cmd = lc.getInt(0), size = lc.getInt(4);
                if (cmd == 0x2) {  // LC_SYMTAB
                    long symoff = lc.getInt(8) & 0xffffffffL;
                    int nsyms = lc.getInt(12);
                    long stroff = lc.getInt(16) & 0xffffffffL;
                    int strsize = lc.getInt(20);
                    if (strsize <= 0 || strsize > MAX_STRTAB || nsyms <= 0) return 0;
                    ByteBuffer syms = read(ch, base + symoff, (int) Math.min((long) nsyms * 16, MAX_STRTAB), ByteOrder.LITTLE_ENDIAN);
                    ByteBuffer str = read(ch, base + stroff, strsize, ByteOrder.LITTLE_ENDIAN);
                    for (int i = 0; i + 16 <= syms.limit(); i += 16) {
                        int strx = syms.getInt(i), type = syms.get(i + 4) & 0xff;
                        boolean undefinedExternal = (type & 0xE0) == 0 && (type & 0x0E) == 0 && (type & 0x01) == 1;
                        if (!undefinedExternal || strx <= 0 || strx >= strsize) continue;
                        int end = strx;
                        while (end < strsize && str.get(end) != 0) end++;
                        byte[] name = new byte[end - strx];
                        str.get(strx, name);
                        rows.add(new SqliteStore.DecompilationResult(
                                new String(name, java.nio.charset.StandardCharsets.UTF_8), IMPORTS_CLASS, "", executableName, "LIGHT"));
                    }
                    break;
                }
                cmdOff += size;
            }
        }
        if (!rows.isEmpty()) {
            store.insertFunctionDecompilations(rows);
            store.insertClass(IMPORTS_CLASS, new org.json.JSONArray(rows.stream().map(SqliteStore.DecompilationResult::functionName).toList()).toString(), executableName);
        }
        log.info("Light ingest: {} imported symbols", rows.size());
        return rows.size();
    }

    /** Absolute [start, end) of the symbol string table, or an empty range when it cannot be read. */
    private static long[] symbolStringTable(Path macho) {
        try (FileChannel ch = FileChannel.open(macho, StandardOpenOption.READ)) {
            long base = sliceOffset(ch);
            ByteBuffer hdr = read(ch, base, 32, ByteOrder.LITTLE_ENDIAN);
            if (hdr.getInt(0) != 0xFEEDFACF) return new long[] {0, 0};
            long cmdOff = base + 32;
            for (int c = 0, n = hdr.getInt(16); c < n; c++) {
                ByteBuffer lc = read(ch, cmdOff, 24, ByteOrder.LITTLE_ENDIAN);
                if (lc.getInt(0) == 0x2) {
                    long start = base + (lc.getInt(16) & 0xffffffffL);
                    return new long[] {start, start + (lc.getInt(20) & 0xffffffffL)};
                }
                cmdOff += lc.getInt(4);
            }
        } catch (IOException | RuntimeException e) {
            log.warn("Light ingest: cannot locate symbol string table: {}", e.getMessage());
        }
        return new long[] {0, 0};
    }

    /** Start of the arm64 (else first) slice for a fat binary, 0 for a thin one. */
    private static long sliceOffset(FileChannel ch) throws IOException {
        ByteBuffer h = read(ch, 0, 8, ByteOrder.BIG_ENDIAN);
        if (h.getInt(0) != 0xCAFEBABE) return 0;
        int n = Math.min(h.getInt(4), 16);
        ByteBuffer arch = read(ch, 8, n * 20, ByteOrder.BIG_ENDIAN);
        long first = -1;
        for (int i = 0; i < n; i++) {
            long off = arch.getInt(i * 20 + 8) & 0xffffffffL;
            if (first < 0) first = off;
            if (arch.getInt(i * 20) == 0x0100000C) return off;
        }
        return Math.max(first, 0);
    }

    private static ByteBuffer read(FileChannel ch, long off, int len, ByteOrder order) throws IOException {
        ByteBuffer b = ByteBuffer.allocate(len).order(order);
        while (b.hasRemaining()) {
            int r = ch.read(b, off + b.position());
            if (r < 0) break;
        }
        b.flip();
        return b;
    }
}
