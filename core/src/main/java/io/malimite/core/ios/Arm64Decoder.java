package io.malimite.core.ios;

/**
 * AArch64 decoder subset: only what the lifter needs to follow pointers and calls (address formation, moves, loads,
 * compares, branches). Everything else decodes to {@link Op#OTHER} carrying the registers it may overwrite, so
 * the lifter never keeps a stale register value alive.
 */
final class Arm64Decoder {

    enum Op {
        ADRP, ADR, ADD_IMM, SUB_IMM, MOV_REG, MOVZ, MOVN, MOVK,
        LDR_IMM, LDR_LIT, STR_IMM, CMP_IMM, CMP_REG,
        BL, B, BCOND, CBZ, CBNZ, TBZ, TBNZ, BR, BLR, RET, OTHER
    }

    /**
     * @param rd   destination (or Rt for loads/stores/cbz); for OTHER the first register clobbered, -1 for none
     * @param rm   second source; for OTHER the second register clobbered, -1 for none
     * @param imm  immediate, branch target address or load address
     * @param aux  condition code (BCOND), access size log2 (LDR/STR), bit number (TBZ), shift (MOVK), writeback flag (OTHER)
     */
    record Insn(Op op, int rd, int rn, int rm, long imm, int aux) {}

    private static final Insn[] NONE = new Insn[0];

    private Arm64Decoder() {}

    private static Insn i(Op op, int rd, int rn, int rm, long imm, int aux) { return new Insn(op, rd, rn, rm, imm, aux); }

    private static Insn other(int rd, int rm, int writebackRn) { return i(Op.OTHER, rd, 0, rm, 0, writebackRn); }

    private static int sext(int v, int bits) { return (v << (32 - bits)) >> (32 - bits); }

    static Insn decode(int w, long pc) {
        int rd = w & 31, rn = (w >>> 5) & 31, rm = (w >>> 16) & 31;

        // ── branches / system ───────────────────────────────────────────────
        if ((w & 0xfc000000) == 0x94000000) return i(Op.BL, 30, 0, 0, pc + ((long) sext(w & 0x3ffffff, 26) << 2), 0);
        if ((w & 0xfc000000) == 0x14000000) return i(Op.B, 0, 0, 0, pc + ((long) sext(w & 0x3ffffff, 26) << 2), 0);
        if ((w & 0xff000010) == 0x54000000) return i(Op.BCOND, 0, 0, 0, pc + ((long) sext((w >>> 5) & 0x7ffff, 19) << 2), w & 15);
        if ((w & 0x7e000000) == 0x34000000)
            return i((w & 0x01000000) == 0 ? Op.CBZ : Op.CBNZ, rd, 0, 0, pc + ((long) sext((w >>> 5) & 0x7ffff, 19) << 2), 0);
        if ((w & 0x7e000000) == 0x36000000)
            return i((w & 0x01000000) == 0 ? Op.TBZ : Op.TBNZ, rd, 0, 0, pc + ((long) sext((w >>> 5) & 0x3fff, 14) << 2),
                    ((w >>> 26) & 0x20) | ((w >>> 19) & 0x1f));
        if ((w & 0xfffffc1f) == 0xd61f0000 || (w & 0xfffff800) == 0xd71f0800 || (w & 0xfffffc1f) == 0xd61f0800)
            return i(Op.BR, 0, rn, 0, 0, 0);                              // br / braa / braaz
        if ((w & 0xfffffc1f) == 0xd63f0000 || (w & 0xfffff800) == 0xd73f0800 || (w & 0xfffffc1f) == 0xd63f0800)
            return i(Op.BLR, 30, rn, 0, 0, 0);                            // blr / blraa / blraaz
        if ((w & 0xfffffc1f) == 0xd65f0000 || w == 0xd65f0bff || w == 0xd65f0fff) return i(Op.RET, 0, 0, 0, 0, 0);
        if ((w & 0xffe00000) == 0xd5200000) return other(rd, -1, 0);      // mrs / sysl write Rt
        if ((w & 0xff000000) == 0xd4000000 || (w & 0xffc00000) == 0xd5000000)
            return other(-1, -1, 0);                                      // svc/brk/hint/barrier/msr: no GPR written
        if ((w & 0x1fe00010) == 0x1a400000 || (w & 0xff20fc07) == 0x1e202000 || (w & 0xff200c10) == 0x1e200400)
            return other(-1, -1, 0);                                      // ccmp/ccmn, fcmp, fccmp: low bits are not a register

        // ── data processing, immediate ──────────────────────────────────────
        if ((w & 0x9f000000) == 0x90000000)
            return i(Op.ADRP, rd, 0, 0, (pc & ~0xfffL) + ((long) (sext(((w >>> 5) & 0x7ffff) << 2 | ((w >>> 29) & 3), 21)) << 12), 0);
        if ((w & 0x9f000000) == 0x10000000)
            return i(Op.ADR, rd, 0, 0, pc + sext(((w >>> 5) & 0x7ffff) << 2 | ((w >>> 29) & 3), 21), 0);
        if ((w & 0x1f000000) == 0x11000000) {                             // add/sub immediate
            boolean sub = (w & 0x40000000) != 0, s = (w & 0x20000000) != 0;
            long imm = ((w >>> 10) & 0xfff) << ((w & 0x400000) != 0 ? 12 : 0);
            if (s && rd == 31) return sub ? i(Op.CMP_IMM, 0, rn, 0, imm, 0) : other(-1, -1, 0);
            return i(sub ? Op.SUB_IMM : Op.ADD_IMM, rd, rn, 0, imm, 0);
        }
        if ((w & 0x7f800000) == 0x52800000) return i(Op.MOVZ, rd, 0, 0, ((long) ((w >>> 5) & 0xffff)) << (((w >>> 21) & 3) * 16), 0);
        if ((w & 0x7f800000) == 0x12800000) return i(Op.MOVN, rd, 0, 0, ~(((long) ((w >>> 5) & 0xffff)) << (((w >>> 21) & 3) * 16)), 0);
        if ((w & 0x7f800000) == 0x72800000) return i(Op.MOVK, rd, 0, 0, (w >>> 5) & 0xffff, ((w >>> 21) & 3) * 16);

        // ── data processing, register ───────────────────────────────────────
        if ((w & 0x7fe0ffe0) == 0x2a0003e0) return i(Op.MOV_REG, rd, 0, rm, 0, 0);  // orr xd, xzr, xm
        if ((w & 0x7f20fc00) == 0x6b000000 && rd == 31 && ((w >>> 22) & 3) == 0)     // subs xzr, xn, xm (cmp)
            return i(Op.CMP_REG, 0, rn, rm, 0, 0);

        // ── loads / stores ──────────────────────────────────────────────────
        boolean simd = (w & 0x04000000) != 0;
        if ((w & 0x3f000000) == 0x39000000) {                             // unsigned immediate, GPR
            int size = (w >>> 30) & 3, opc = (w >>> 22) & 3;
            long imm = ((long) ((w >>> 10) & 0xfff)) << size;
            if (opc == 0) return i(Op.STR_IMM, rd, rn, 0, imm, size);
            if (opc == 1) return i(Op.LDR_IMM, rd, rn, 0, imm, size);
            return other(rd, -1, 0);
        }
        if ((w & 0x3f000000) == 0x18000000) {                             // load literal, GPR
            int opc = (w >>> 30) & 3;
            long addr = pc + ((long) sext((w >>> 5) & 0x7ffff, 19) << 2);
            return opc == 1 ? i(Op.LDR_LIT, rd, 0, 0, addr, 3) : opc == 0 ? i(Op.LDR_LIT, rd, 0, 0, addr, 2) : other(rd, -1, 0);
        }
        int op0 = (w >>> 25) & 15;
        boolean loadStore = (op0 & 5) == 4;                               // x1x0
        if (loadStore) {
            if (simd) return other(-1, -1, (w & 0x3b200000) == 0x38000000 && (w & 0x400) != 0 ? 1 : 0);
            boolean load = (w & 0x00400000) != 0;
            boolean pair = (w & 0x3a000000) == 0x28000000;
            boolean writeback = pair ? ((w >>> 23) & 3) != 2 : (w & 0x3f200000) == 0x38000000 && (w & 0x400) != 0;
            if (pair) return other(load ? rd : -1, load ? (w >>> 10) & 31 : -1, writeback ? 1 : 0);
            boolean excl = (w & 0x3f000000) == 0x08000000, atomic = (w & 0x3f200c00) == 0x38200000;
            int second = excl || atomic ? rm : -1;                        // stxr status / ldadd source register
            return other(load || excl || atomic ? rd : -1, second, writeback ? 1 : 0);
        }
        // everything else: assume Rd (bits 0-4) is written
        if (op0 == 10 || op0 == 11) return other(-1, -1, 0);
        return other(rd == 31 ? -1 : rd, -1, 0);
    }
}
