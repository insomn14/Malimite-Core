package io.malimite.core.ios;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Memory-mapped, read-only view of one arm64 Mach-O slice. Parses just what the native iOS engine needs:
 * segments/sections, symbols, function starts, encryption flag and a resolved pointer view (chained fixups or
 * classic dyld bind info), so metadata walkers can follow pointers without caring how the binary was linked.
 * All reads are absolute, so one image can be shared by parallel lifting threads.
 */
final class MachOImage implements AutoCloseable {

    record Segment(String name, long vmaddr, long vmsize, long fileoff, long filesize) {}

    record Section(String segment, String name, long addr, long size, long offset, int flags, int reserved1, int reserved2) {
        int type() { return flags & 0xff; }
    }

    record Symbol(String name, long addr, int type, int sect) {
        boolean undefined() { return (type & 0x0e) == 0 && (type & 0x01) == 1; }
    }

    private static final int MH_MAGIC_64 = 0xFEEDFACF;
    private static final int CPU_ARM64 = 0x0100000C;
    static final int S_CSTRING_LITERALS = 0x2;

    final ByteBuffer buf;
    final List<Segment> segments = new ArrayList<>();
    final List<Section> sections = new ArrayList<>();
    final List<String> importNames = new ArrayList<>();
    long[] functionStarts = new long[0];
    boolean encrypted;
    long baseVm;

    private final FileChannel channel;
    private int symoff, nsyms, stroff, strsize;
    private final Map<String, Integer> importIndex = new HashMap<>();
    private long[] fixLoc = new long[1024];
    private long[] fixVal = new long[1024];
    private int fixN;
    private boolean fixSorted = true;

    private MachOImage(FileChannel channel, ByteBuffer buf) {
        this.channel = channel;
        this.buf = buf;
    }

    /** Maps the arm64 slice (fat or thin) of {@code file}. Throws for 32-bit, big-endian or non-arm64 binaries. */
    static MachOImage open(Path file) throws IOException {
        FileChannel ch = FileChannel.open(file, StandardOpenOption.READ);
        try {
            long off = 0, len = ch.size();
            ByteBuffer h = ByteBuffer.allocate(8).order(ByteOrder.BIG_ENDIAN);
            ch.read(h, 0);
            int magic = h.getInt(0);
            if (magic == 0xCAFEBABE || magic == 0xCAFEBABF) {
                boolean wide = magic == 0xCAFEBABF;
                int n = Math.min(h.getInt(4), 16), stride = wide ? 32 : 20;
                ByteBuffer a = ByteBuffer.allocate(n * stride).order(ByteOrder.BIG_ENDIAN);
                ch.read(a, 8);
                long fo = -1, fl = 0;
                for (int i = 0, p = 0; i < n; i++, p += stride) {
                    long o = wide ? a.getLong(p + 8) : a.getInt(p + 8) & 0xffffffffL;
                    long l = wide ? a.getLong(p + 16) : a.getInt(p + 12) & 0xffffffffL;
                    if (a.getInt(p) == CPU_ARM64) { fo = o; fl = l; break; }
                }
                if (fo < 0) throw new IOException("fat Mach-O has no arm64 slice");
                off = fo; len = fl;
            }
            if (len > Integer.MAX_VALUE) throw new IOException("Mach-O slice larger than 2GB is not supported");
            ByteBuffer b = ch.map(FileChannel.MapMode.READ_ONLY, off, len).order(ByteOrder.LITTLE_ENDIAN);
            if (b.getInt(0) != MH_MAGIC_64) throw new IOException("not a 64-bit little-endian Mach-O");
            if (b.getInt(4) != CPU_ARM64) throw new IOException("native iOS engine supports arm64 only");
            MachOImage img = new MachOImage(ch, b);
            img.parseLoadCommands();
            return img;
        } catch (IOException | RuntimeException e) {
            ch.close();
            throw e;
        }
    }

    @Override public void close() throws IOException { channel.close(); }

    // ── load commands ───────────────────────────────────────────────────────

    private void parseLoadCommands() {
        int ncmds = buf.getInt(16);
        int p = 32;
        int chainedOff = -1, chainedSize = 0, funcOff = -1, funcSize = 0;
        int dyldInfo = -1;
        for (int c = 0; c < ncmds; c++) {
            int cmd = buf.getInt(p), size = buf.getInt(p + 4);
            switch (cmd) {
                case 0x19 -> {  // LC_SEGMENT_64
                    Segment seg = new Segment(fixed16(p + 8), buf.getLong(p + 24), buf.getLong(p + 32),
                            buf.getLong(p + 40), buf.getLong(p + 48));
                    segments.add(seg);
                    if (seg.name().equals("__TEXT")) baseVm = seg.vmaddr();
                    int nsects = buf.getInt(p + 64);
                    for (int s = 0, q = p + 72; s < nsects; s++, q += 80)
                        sections.add(new Section(fixed16(q + 16), fixed16(q), buf.getLong(q + 32), buf.getLong(q + 40),
                                buf.getInt(q + 48) & 0xffffffffL, buf.getInt(q + 64), buf.getInt(q + 68), buf.getInt(q + 72)));
                }
                case 0x2 -> {  // LC_SYMTAB
                    symoff = buf.getInt(p + 8); nsyms = buf.getInt(p + 12);
                    stroff = buf.getInt(p + 16); strsize = buf.getInt(p + 20);
                }
                case 0x2C, 0x21 -> encrypted = buf.getInt(p + 16) != 0;  // LC_ENCRYPTION_INFO(_64): cryptid
                case 0x80000034 -> { chainedOff = buf.getInt(p + 8); chainedSize = buf.getInt(p + 12); }
                case 0x26 -> { funcOff = buf.getInt(p + 8); funcSize = buf.getInt(p + 12); }
                case 0x22, 0x80000022 -> dyldInfo = p;
                default -> { }
            }
            p += size;
        }
        if (funcOff > 0) functionStarts = parseFunctionStarts(funcOff, funcSize);
        if (chainedOff > 0) parseChainedFixups(chainedOff, chainedSize);
        else if (dyldInfo >= 0) {
            parseBinds(buf.getInt(dyldInfo + 16), buf.getInt(dyldInfo + 20), false);
            parseBinds(buf.getInt(dyldInfo + 24), buf.getInt(dyldInfo + 28), false);
            parseBinds(buf.getInt(dyldInfo + 32), buf.getInt(dyldInfo + 36), true);
        }
        sortFixups();
    }

    private String fixed16(int at) {
        int n = 0;
        while (n < 16 && buf.get(at + n) != 0) n++;
        byte[] b = new byte[n];
        buf.get(at, b);
        return new String(b, StandardCharsets.US_ASCII);
    }

    private long[] parseFunctionStarts(int off, int size) {
        long[] out = new long[1024];
        int n = 0, p = off, end = off + size;
        long addr = baseVm;
        while (p < end) {
            long delta = 0; int shift = 0; int b;
            do {
                b = buf.get(p++) & 0xff;
                delta |= (long) (b & 0x7f) << shift;
                shift += 7;
            } while ((b & 0x80) != 0 && p < end);
            if (delta == 0) break;
            addr += delta;
            if (n == out.length) out = Arrays.copyOf(out, n * 2);
            out[n++] = addr;
        }
        return Arrays.copyOf(out, n);
    }

    // ── fixups / pointers ───────────────────────────────────────────────────

    private int importId(String name) {
        Integer i = importIndex.get(name);
        if (i != null) return i;
        importNames.add(name);
        importIndex.put(name, importNames.size() - 1);
        return importNames.size() - 1;
    }

    private void addFixup(long off, long val) {
        if (fixN == fixLoc.length) {
            fixLoc = Arrays.copyOf(fixLoc, fixN * 2);
            fixVal = Arrays.copyOf(fixVal, fixN * 2);
        }
        if (fixN > 0 && off < fixLoc[fixN - 1]) fixSorted = false;
        fixLoc[fixN] = off;
        fixVal[fixN++] = val;
    }

    private void sortFixups() {
        if (fixSorted) return;
        Integer[] order = new Integer[fixN];
        for (int i = 0; i < fixN; i++) order[i] = i;
        Arrays.sort(order, (a, b) -> Long.compare(fixLoc[a], fixLoc[b]));
        long[] l = new long[fixN], v = new long[fixN];
        for (int i = 0; i < fixN; i++) { l[i] = fixLoc[order[i]]; v[i] = fixVal[order[i]]; }
        fixLoc = l; fixVal = v; fixSorted = true;
    }

    private static final long BIND_FLAG = Long.MIN_VALUE;

    private void parseChainedFixups(int off, int size) {
        int startsOff = buf.getInt(off + 4), importsOff = buf.getInt(off + 8), symsOff = buf.getInt(off + 12);
        int count = buf.getInt(off + 16), fmt = buf.getInt(off + 20);
        int[] ordinalToId = new int[count];
        for (int i = 0; i < count; i++) {
            long nameOff;
            switch (fmt) {
                case 1 -> nameOff = (buf.getInt(off + importsOff + i * 4) >>> 9) & 0x7fffff;
                case 2 -> nameOff = (buf.getInt(off + importsOff + i * 8) >>> 9) & 0x7fffff;
                case 3 -> nameOff = (int) (buf.getLong(off + importsOff + i * 16) >>> 32);
                default -> { return; }
            }
            ordinalToId[i] = importId(cstr(off + symsOff + (int) nameOff));
        }
        int starts = off + startsOff;
        int segCount = buf.getInt(starts);
        for (int s = 0; s < segCount && s < segments.size(); s++) {
            int segInfoOff = buf.getInt(starts + 4 + s * 4);
            if (segInfoOff == 0) continue;
            int info = starts + segInfoOff;
            int pageSize = buf.getShort(info + 4) & 0xffff;
            int format = buf.getShort(info + 6) & 0xffff;
            int pageCount = buf.getShort(info + 20) & 0xffff;
            Segment seg = segments.get(s);
            for (int pg = 0; pg < pageCount; pg++) {
                int ps = buf.getShort(info + 22 + pg * 2) & 0xffff;
                if (ps == 0xFFFF) continue;
                if ((ps & 0x8000) != 0) {  // multi-start: ps indexes an overflow list in the same array
                    int idx = ps & 0x7fff;
                    while (true) {
                        int e = buf.getShort(info + 22 + idx * 2) & 0xffff;
                        walkChain(seg.fileoff() + (long) pg * pageSize + (e & 0x7fff), format, ordinalToId);
                        if ((e & 0x8000) != 0) break;
                        idx++;
                    }
                } else {
                    walkChain(seg.fileoff() + (long) pg * pageSize + ps, format, ordinalToId);
                }
            }
        }
    }

    private void walkChain(long loc, int format, int[] ordinalToId) {
        boolean arm64e = format == 1 || format == 9 || format == 12;
        int stride = arm64e ? 8 : 4;
        for (int guard = 0; guard < (1 << 20); guard++) {
            if (loc < 0 || loc + 8 > buf.limit()) return;
            long raw = buf.getLong((int) loc);
            long next;
            if (arm64e) {
                boolean auth = raw < 0, bind = ((raw >>> 62) & 1) != 0;
                next = (raw >>> 51) & 0x7ff;
                if (bind) {
                    int ord = (int) (raw & (format == 12 ? 0xffffffL : 0xffffL));
                    if (ord < ordinalToId.length) addFixup(loc, BIND_FLAG | ordinalToId[ord]);
                } else if (auth) {
                    addFixup(loc, baseVm + (raw & 0xffffffffL));
                } else {
                    long t = raw & 0x7ffffffffffL;
                    addFixup(loc, format == 1 ? t : baseVm + t);
                }
            } else {
                boolean bind = raw < 0;
                next = (raw >>> 51) & 0xfff;
                if (bind) {
                    int ord = (int) (raw & 0xffffffL);
                    if (ord < ordinalToId.length) addFixup(loc, BIND_FLAG | ordinalToId[ord]);
                } else {
                    long t = raw & 0xfffffffffL;
                    addFixup(loc, format == 6 ? baseVm + t : t);
                }
            }
            if (next == 0) return;
            loc += next * stride;
        }
    }

    /** Classic dyld bind opcodes (pre-chained-fixups binaries). */
    private void parseBinds(int off, int size, boolean lazy) {
        if (off <= 0 || size <= 0) return;
        int p = off, end = off + size;
        String sym = null;
        long segIdx = 0, segOff = 0;
        while (p < end) {
            int b = buf.get(p++) & 0xff, op = b & 0xf0, imm = b & 0x0f;
            switch (op) {
                case 0x00 -> { if (!lazy) return; sym = null; }
                case 0x10, 0x30, 0x50 -> { }
                case 0x20, 0x80 -> {
                    long[] r = uleb(p); p = (int) r[1];
                    if (op == 0x80) segOff += r[0];
                }
                case 0x40 -> {
                    int e = p;
                    while (buf.get(e) != 0) e++;
                    byte[] n = new byte[e - p];
                    buf.get(p, n);
                    sym = new String(n, StandardCharsets.UTF_8);
                    p = e + 1;
                }
                case 0x60 -> { while ((buf.get(p++) & 0x80) != 0) { } }
                case 0x70 -> { segIdx = imm; long[] r = uleb(p); p = (int) r[1]; segOff = r[0]; }
                case 0x90 -> { bindAt(segIdx, segOff, sym); segOff += 8; }
                case 0xA0 -> { bindAt(segIdx, segOff, sym); long[] r = uleb(p); p = (int) r[1]; segOff += 8 + r[0]; }
                case 0xB0 -> { bindAt(segIdx, segOff, sym); segOff += 8 + (long) imm * 8; }
                case 0xC0 -> {
                    long[] c = uleb(p); long[] k = uleb((int) c[1]); p = (int) k[1];
                    for (long i = 0; i < c[0]; i++) { bindAt(segIdx, segOff, sym); segOff += 8 + k[0]; }
                }
                default -> { return; }
            }
        }
    }

    private void bindAt(long segIdx, long segOff, String sym) {
        if (sym == null || segIdx >= segments.size()) return;
        addFixup(segments.get((int) segIdx).fileoff() + segOff, BIND_FLAG | importId(sym));
    }

    private long[] uleb(int p) {
        long v = 0; int shift = 0; int b;
        do { b = buf.get(p++) & 0xff; v |= (long) (b & 0x7f) << shift; shift += 7; } while ((b & 0x80) != 0);
        return new long[] {v, p};
    }

    // ── address translation and typed reads ─────────────────────────────────

    /** File offset (within the slice) for a vm address, or -1 when unmapped or zero-fill. */
    long offsetOf(long vmaddr) {
        for (Segment s : segments)
            if (vmaddr >= s.vmaddr() && vmaddr < s.vmaddr() + s.filesize())
                return s.fileoff() + (vmaddr - s.vmaddr());
        return -1;
    }

    long vmaddrOf(long fileoff) {
        for (Segment s : segments)
            if (fileoff >= s.fileoff() && fileoff < s.fileoff() + s.filesize() && s.filesize() > 0)
                return s.vmaddr() + (fileoff - s.fileoff());
        return -1;
    }

    /** Pointer stored at {@code vmaddr} with fixups applied; 0 for a bound (external) pointer or an unmapped address. */
    long ptr(long vmaddr) {
        long off = offsetOf(vmaddr);
        if (off < 0 || off + 8 > buf.limit()) return 0;
        int i = Arrays.binarySearch(fixLoc, 0, fixN, off);
        if (i >= 0) return fixVal[i] < 0 ? 0 : fixVal[i];
        return buf.getLong((int) off);
    }

    /** Imported symbol the pointer at {@code vmaddr} is bound to (e.g. {@code _OBJC_CLASS_$_NSObject}), else null. */
    String bindName(long vmaddr) {
        long off = offsetOf(vmaddr);
        if (off < 0) return null;
        int i = Arrays.binarySearch(fixLoc, 0, fixN, off);
        return i >= 0 && fixVal[i] < 0 ? importNames.get((int) (fixVal[i] & 0x7fffffff)) : null;
    }

    int u32(long vmaddr) {
        long off = offsetOf(vmaddr);
        return off < 0 || off + 4 > buf.limit() ? 0 : buf.getInt((int) off);
    }

    long u64(long vmaddr) {
        long off = offsetOf(vmaddr);
        return off < 0 || off + 8 > buf.limit() ? 0 : buf.getLong((int) off);
    }

    /** NUL-terminated string at a vm address, or null when unmapped. */
    String cstringAt(long vmaddr) {
        long off = offsetOf(vmaddr);
        return off < 0 ? null : cstr((int) off);
    }

    String cstr(int off) {
        int e = off;
        while (e < buf.limit() && buf.get(e) != 0) e++;
        byte[] b = new byte[e - off];
        buf.get(off, b);
        return new String(b, StandardCharsets.UTF_8);
    }

    Section section(String name) {
        for (Section s : sections) if (s.name().equals(name)) return s;
        return null;
    }

    Section sectionOf(long vmaddr) {
        for (Section s : sections) if (vmaddr >= s.addr() && vmaddr < s.addr() + s.size()) return s;
        return null;
    }

    // ── symbols ─────────────────────────────────────────────────────────────

    List<Symbol> symbols() {
        List<Symbol> out = new ArrayList<>();
        if (nsyms <= 0 || strsize <= 0) return out;
        for (int i = 0; i < nsyms; i++) {
            int p = symoff + i * 16;
            if (p + 16 > buf.limit()) break;
            int strx = buf.getInt(p), type = buf.get(p + 4) & 0xff, sect = buf.get(p + 5) & 0xff;
            if (strx <= 0 || strx >= strsize || (type & 0xe0) != 0) continue;  // skip stabs / unnamed
            out.add(new Symbol(cstr(stroff + strx), buf.getLong(p + 8), type, sect));
        }
        return out;
    }

    /** Imported symbol names from fixups/binds plus undefined external symbols from LC_SYMTAB (deduplicated). */
    List<String> imports() {
        java.util.LinkedHashSet<String> out = new java.util.LinkedHashSet<>(importNames);
        for (Symbol s : symbols()) if (s.undefined() && (s.type() & 0x01) == 1) out.add(s.name());
        return new ArrayList<>(out);
    }

    boolean isSwift() {
        for (Section s : sections) if (s.name().startsWith("__swift5_")) return true;
        return false;
    }
}
