package io.malimite.core.ios;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Turns one function into compact C-like pseudocode: calls with resolved import/selector/class/literal arguments,
 * conditional branches as {@code if (...) goto}, string stores and returns. Register moves and arithmetic are folded
 * into the tracked values instead of printed. Simple forward skips and backward loops become blocks ({@link Structurer});
 * everything else stays a label and a goto.
 */
final class Lifter {

    record Ref(String target, String targetClass, int line) {}

    /** @param interesting true when the body references at least one named callee or literal */
    record Lifted(String body, List<Ref> refs, boolean interesting) {}

    static final int MAX_INSNS = 8192;
    private static final int MAX_LINES = 600;
    /** First body line number: callers prepend a three-line header ({@code // Class}, {@code // Function}, blank). */
    private static final int HEADER_LINES = 3;

    private static final Set<String> KEEP_ARG0 = Set.of("objc_retain", "objc_retainAutoreleasedReturnValue",
            "objc_autoreleaseReturnValue", "objc_autorelease", "objc_retainAutorelease", "objc_retainAutoreleaseReturnValue",
            "objc_unsafeClaimAutoreleasedReturnValue", "swift_retain", "swift_bridgeObjectRetain", "swift_unknownObjectRetain",
            "swift_bridgeObjectRetain_n", "objc_retainBlock", "objc_opt_self");
    private static final Set<String> DROPPED = Set.of("objc_release", "swift_release", "swift_bridgeObjectRelease",
            "swift_unknownObjectRelease", "objc_storeStrong", "objc_destroyWeak", "objc_storeWeak", "swift_release_n",
            "swift_bridgeObjectRelease_n", "objc_autoreleasePoolPop", "_objc_autoreleasePoolPop", "swift_endAccess",
            "swift_beginAccess", "__chkstk_darwin");

    private final MachOImage img;
    private final ObjcMetadata objc;
    private final StubResolver stubs;
    private final Map<Long, String> symbols;

    Lifter(MachOImage img, ObjcMetadata objc, StubResolver stubs, Map<Long, String> symbols) {
        this.img = img;
        this.objc = objc;
        this.stubs = stubs;
        this.symbols = symbols;
    }

    Lifted lift(long start, long end, boolean objcMethod) {
        long off = img.offsetOf(start);
        int n = off < 0 ? 0 : (int) Math.min(Math.min((end - start) / 4, MAX_INSNS), (img.buf.limit() - off) / 4);
        Arm64Decoder.Insn[] ins = new Arm64Decoder.Insn[n];
        Set<Long> labels = new HashSet<>();
        for (int i = 0; i < n; i++) {
            ins[i] = Arm64Decoder.decode(img.buf.getInt((int) off + 4 * i), start + 4L * i);
            switch (ins[i].op()) {
                case B, BCOND, CBZ, CBNZ, TBZ, TBNZ -> {
                    long t = ins[i].imm();
                    if (t >= start && t < start + 4L * n) labels.add(t);
                }
                default -> { }
            }
        }

        Run run = new Run(start, labels, objcMethod);
        for (int i = 0; i < n && run.lines < MAX_LINES; i++) run.step(ins[i], start + 4L * i, i);
        String body = Structurer.render(run.stmts) + (run.lines >= MAX_LINES ? "// ... truncated\n" : "");
        return new Lifted(body, run.refs, run.interesting);
    }

    /** Per-function state. */
    private final class Run {
        final Tracker t = new Tracker(img, objc);
        final List<Structurer.Stmt> stmts = new ArrayList<>();
        final List<Ref> refs = new ArrayList<>();
        final Set<Long> labels;
        final boolean objcMethod;
        final long start;
        int lines;
        boolean interesting;
        String cmpA, cmpB;

        Run(long start, Set<Long> labels, boolean objcMethod) {
            this.start = start;
            this.labels = labels;
            this.objcMethod = objcMethod;
            seedParams();
        }

        void seedParams() {
            for (int i = 0; i < 8; i++)
                t.r[i] = Val.named(objcMethod && i == 0 ? "self" : objcMethod && i == 1 ? "_cmd" : "param_" + (i + 1));
        }

        void emit(String stmt) {
            stmts.add(Structurer.Stmt.plain(stmt));
            lines++;
        }

        /** {@code if (cond) goto target;} (or a bare goto when cond is null); {@code neg} is the opposite test, if known. */
        void branch(String cond, String neg, long target) {
            if (labels.contains(target)) {
                stmts.add(Structurer.Stmt.jump(cond, neg, target));
                lines++;
            } else {
                emit((cond == null ? "" : "if (" + cond + ") ") + "goto 0x" + Long.toHexString(target) + ";");
            }
        }

        int nextLine() { return HEADER_LINES + lines + 1; }

        String text(int reg) {
            Val v = t.literalize(t.reg(reg));
            return v == null ? "x" + reg : v.show();
        }

        void step(Arm64Decoder.Insn in, long pc, int idx) {
            if (labels.contains(pc)) {
                t.resetAll();
                cmpA = cmpB = null;
                stmts.add(Structurer.Stmt.label(pc));
                lines++;
            }
            switch (in.op()) {
                case BL -> call(callee(in.imm()), false);
                case BLR -> call(indirect(in.rn()), false);
                case BR -> {
                    Callee c = indirect(in.rn());
                    if (c.named()) call(c, true);
                    else emit("goto *" + text(in.rn()) + ";");  // jump table / computed branch
                }
                case B -> {
                    if (labels.contains(in.imm())) branch(null, null, in.imm());
                    else call(callee(in.imm()), true);
                }
                case BCOND -> branch(cond(in.aux()), in.aux() < 14 ? cond(in.aux() ^ 1) : null, in.imm());
                case CBZ -> branch(text(in.rd()) + " == 0", text(in.rd()) + " != 0", in.imm());
                case CBNZ -> branch(text(in.rd()) + " != 0", text(in.rd()) + " == 0", in.imm());
                case TBZ -> branch(bit(in.rd(), in.aux()) + " == 0", bit(in.rd(), in.aux()) + " != 0", in.imm());
                case TBNZ -> branch(bit(in.rd(), in.aux()) + " != 0", bit(in.rd(), in.aux()) + " == 0", in.imm());
                case CMP_IMM -> { cmpA = text(in.rn()); cmpB = Val.konst(in.imm()).show(); }
                case CMP_REG -> { cmpA = text(in.rn()); cmpB = text(in.rm()); }
                case RET -> {
                    Val x0 = t.reg(0);
                    emit(x0 != null && (x0.isLiteral() || x0.k == Val.K.RET || x0.k == Val.K.CONST || x0.k == Val.K.MEM)
                            ? "return " + x0.show() + ";" : "return;");
                }
                case STR_IMM -> {
                    Val v = t.literalize(t.reg(in.rd()));
                    if (v != null && v.isLiteral()) {
                        interesting = true;
                        String base = in.rn() == 31 ? "sp" : text(in.rn());
                        emit("*(" + base + " + 0x" + Long.toHexString(in.imm()) + ") = " + v.show() + ";");
                    }
                }
                default -> t.step(in);
            }
        }

        /** C-call argument: previous call results are shown as the raw register, since x0 is often stale there. */
        String cArg(int reg) {
            Val v = t.reg(reg);
            return v != null && v.k == Val.K.RET ? "x" + reg : text(reg);
        }

        String bit(int reg, int n) {
            return "(" + text(reg) + " & (1 << " + n + "))";
        }

        String cond(int cc) {
            String a = cmpA, b = cmpB;
            if (a == null) return switch (cc) {
                case 0 -> "flags.eq"; case 1 -> "!flags.eq"; case 2 -> "flags.carry"; case 3 -> "!flags.carry";
                case 4 -> "flags.neg"; case 5 -> "!flags.neg"; case 6 -> "flags.overflow"; case 7 -> "!flags.overflow";
                case 8 -> "flags.hi"; case 9 -> "!flags.hi"; case 10 -> "flags.ge"; case 11 -> "!flags.ge";
                case 12 -> "flags.gt"; case 13 -> "!flags.gt"; default -> "1";
            };
            return switch (cc) {
                case 0 -> a + " == " + b; case 1 -> a + " != " + b;
                case 2 -> "(unsigned)" + a + " >= " + b; case 3 -> "(unsigned)" + a + " < " + b;
                case 4 -> a + " < 0"; case 5 -> a + " >= 0";
                case 6 -> "overflow(" + a + ", " + b + ")"; case 7 -> "!overflow(" + a + ", " + b + ")";
                case 8 -> "(unsigned)" + a + " > " + b; case 9 -> "(unsigned)" + a + " <= " + b;
                case 10 -> a + " >= " + b; case 11 -> a + " < " + b; case 12 -> a + " > " + b; case 13 -> a + " <= " + b;
                default -> "1";
            };
        }

        // ── calls ───────────────────────────────────────────────────────────

        /** @param name display name; @param sel selector fixed by an objc stub, else null; @param named false for sub_/indirect targets */
        private record Callee(String name, String sel, boolean named, String cls) {}

        Callee callee(long target) {
            StubResolver.Callee c = stubs.resolve(target);
            if (c != null) return new Callee(c.name(), c.sel(), true, null);
            ObjcMetadata.Method m = objc.byImp.get(target);
            if (m != null)
                return new Callee((m.classMethod() ? "+[" : "-[") + m.cls() + " " + m.selector() + "]", null, true, m.cls());
            String sym = symbols.get(target);
            if (sym != null) return new Callee(sym, null, true, null);
            return new Callee("sub_" + Long.toHexString(target), null, false, null);
        }

        Callee indirect(int reg) {
            Val v = t.reg(reg);
            if (v != null && v.k == Val.K.SYM) return new Callee(v.s, null, true, null);
            if (v != null && v.k == Val.K.ADDR) return callee(v.n);
            return new Callee("(*" + (v == null ? "x" + reg : v.show()) + ")", null, false, null);
        }

        /** objc_retain / objc_release families, including the register-specific {@code objc_release_x25} variants. */
        private int retainArgReg(String name) {
            int us = name.lastIndexOf("_x");
            if (us > 0 && us + 2 < name.length() && name.substring(us + 2).chars().allMatch(Character::isDigit))
                return Integer.parseInt(name.substring(us + 2));
            return 0;
        }

        void call(Callee c, boolean tail) {
            String name = c.name();
            if (KEEP_ARG0.contains(name) || name.startsWith("objc_retain") || name.startsWith("objc_autorelease")) {
                Val keep = t.reg(retainArgReg(name));  // result is its argument, nothing worth printing
                t.clobberCallerSaved();
                t.r[0] = keep;
                if (tail) emit("return;");
                return;
            }
            if (DROPPED.contains(name) || name.startsWith("objc_release") || name.startsWith("objc_storeStrong")) {
                t.clobberCallerSaved();
                if (tail) emit("return;");
                return;
            }
            String expr, refTarget, refClass = "Unknown";
            boolean msgSend = name.startsWith("objc_msgSend");
            if (msgSend) {
                String sel = c.sel();
                if (sel == null && name.startsWith("objc_msgSend$")) sel = name.substring("objc_msgSend$".length());
                Val selV = t.reg(1);
                if (sel == null && selV != null && selV.k == Val.K.SEL) sel = selV.s;
                Val recv = t.literalize(t.reg(0));
                String recvText = name.startsWith("objc_msgSendSuper") ? "super" : recv == null ? "x0" : recv.show();
                if (recv != null && recv.k == Val.K.CLS) refClass = recv.s;
                StringBuilder sb = new StringBuilder("objc_msgSend(").append(recvText).append(", ");
                if (sel != null) {
                    sb.append(Val.quote(sel));
                    int argc = 0;
                    for (int i = 0; i < sel.length(); i++) if (sel.charAt(i) == ':') argc++;
                    for (int i = 0; i < argc && 2 + i < 8; i++) sb.append(", ").append(text(2 + i));
                    refTarget = sel;
                } else {
                    sb.append(text(1));
                    refTarget = "objc_msgSend";
                }
                expr = sb.append(')').toString();
                interesting = true;
            } else {
                int last = -1;
                for (int i = 0; i < 8; i++) {
                    Val v = t.reg(i);
                    if (v != null && v.k != Val.K.NAMED) last = i;
                }
                StringBuilder sb = new StringBuilder(name).append('(');
                for (int i = 0; i <= last; i++) sb.append(i == 0 ? "" : ", ").append(cArg(i));
                expr = sb.append(')').toString();
                refTarget = name.startsWith("-[") || name.startsWith("+[")
                        ? name.substring(name.indexOf(' ') + 1, name.length() - 1) : name;
                if (c.cls() != null) refClass = c.cls();
                if (c.named()) interesting = true;
                for (int i = 0; i <= last; i++) {
                    Val v = t.literalize(t.reg(i));
                    if (v != null && v.isLiteral()) interesting = true;
                }
            }
            refs.add(new Ref(refTarget, refClass, nextLine()));
            emit(tail ? "return " + expr + ";" : expr + ";");
            t.clobberCallerSaved();
            cmpA = cmpB = null;
            if (!tail) t.r[0] = Val.ret(expr);
        }
    }
}
