package io.malimite.core.ios;

import java.nio.charset.StandardCharsets;

/** Abstract register file: replays data-flow instructions so addresses, literals, selectors and imports can be named at calls. */
final class Tracker {

    private final MachOImage img;
    private final ObjcMetadata objc;
    final Val[] r = new Val[32];

    Tracker(MachOImage img, ObjcMetadata objc) {
        this.img = img;
        this.objc = objc;
    }

    Val reg(int i) { return i >= 31 ? (i == 31 ? Val.konst(0) : null) : r[i]; }

    private void set(int i, Val v) { if (i < 31) r[i] = v; }

    void resetAll() { java.util.Arrays.fill(r, null); }

    /** Registers a call may overwrite (x0-x18 and the link register). */
    void clobberCallerSaved() {
        for (int i = 0; i <= 18; i++) r[i] = null;
        r[30] = null;
    }

    /** Applies a non-control-flow instruction. */
    void step(Arm64Decoder.Insn in) {
        switch (in.op()) {
            case ADRP, ADR -> set(in.rd(), Val.addr(in.imm()));
            case ADD_IMM -> {
                Val b = in.rn() == 31 ? null : r[in.rn()];
                set(in.rd(), b == null ? null : b.k == Val.K.ADDR ? Val.addr(b.n + in.imm())
                        : b.k == Val.K.CONST ? Val.konst(b.n + in.imm()) : null);
            }
            case SUB_IMM -> {
                Val b = in.rn() == 31 ? null : r[in.rn()];
                set(in.rd(), b == null ? null : b.k == Val.K.ADDR ? Val.addr(b.n - in.imm())
                        : b.k == Val.K.CONST ? Val.konst(b.n - in.imm()) : null);
            }
            case MOV_REG -> set(in.rd(), reg(in.rm()));
            case MOVZ, MOVN -> set(in.rd(), Val.konst(in.imm()));
            case MOVK -> {
                Val b = r[in.rd() & 31];
                long mask = 0xffffL << in.aux();
                set(in.rd(), b != null && b.k == Val.K.CONST ? Val.konst((b.n & ~mask) | (in.imm() << in.aux())) : null);
            }
            case LDR_IMM -> {
                Val b = in.rn() == 31 ? null : r[in.rn()];
                set(in.rd(), in.aux() == 3 && b != null && b.k == Val.K.ADDR ? load(b.n + in.imm()) : null);
            }
            case LDR_LIT -> set(in.rd(), in.aux() == 3 ? load(in.imm()) : null);
            case OTHER -> {
                if (in.rd() >= 0) set(in.rd(), null);
                if (in.rm() >= 0) set(in.rm(), null);
                if (in.aux() == 1) set(in.rn(), null);
            }
            default -> { }  // STR/CMP/branches never write a tracked GPR
        }
    }

    /** Value of the 8-byte pointer stored at {@code slot}. */
    Val load(long slot) {
        MachOImage.Section s = img.sectionOf(slot);
        String sn = s == null ? "" : s.name();
        switch (sn) {
            case "__objc_selrefs" -> {
                String sel = img.cstringAt(img.ptr(slot));
                return sel == null ? null : Val.sel(sel);
            }
            case "__objc_classrefs", "__objc_superrefs" -> {
                String c = objc.classRefName(slot);
                return c == null ? null : Val.cls(c);
            }
            default -> { }
        }
        String bound = img.bindName(slot);
        if (bound != null) return Val.sym(bound);
        long p = img.ptr(slot);
        return p == 0 ? null : Val.addr(p);
    }

    /** Turns an address into the string literal it points at, when it points into a string section. */
    Val literalize(Val v) {
        if (v == null || v.k != Val.K.ADDR) return v;
        MachOImage.Section s = img.sectionOf(v.n);
        if (s == null) return v;
        if (s.type() == MachOImage.S_CSTRING_LITERALS) {
            String c = img.cstringAt(v.n);
            return c == null ? v : Val.str(c);
        }
        if (s.name().equals("__cfstring")) {
            Val cf = cfString(v.n);
            return cf == null ? v : cf;
        }
        return v;
    }

    private Val cfString(long entry) {
        long strPtr = img.ptr(entry + 16), len = img.u64(entry + 24);
        if (strPtr == 0 || len < 0 || len > 100_000) return null;
        boolean utf16 = (img.u32(entry + 8) & 0x10) != 0;
        long off = img.offsetOf(strPtr);
        if (off < 0) return null;
        int bytes = (int) (utf16 ? len * 2 : len);
        if (off + bytes > img.buf.limit()) return null;
        byte[] b = new byte[bytes];
        img.buf.get((int) off, b);
        return Val.cfstr(new String(b, utf16 ? StandardCharsets.UTF_16LE : StandardCharsets.UTF_8));
    }
}
