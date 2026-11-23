package io.malimite.core.ios;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Turns the goto shapes compilers emit most into blocks, one output line per input line (so the line numbers the
 * lifter recorded for {@code FunctionReferences} stay valid; lines a block absorbs, such as a consumed label, come out
 * blank):
 * <ul>
 *   <li>forward skip {@code if (c) goto L; body L:} becomes {@code if (!c) { body }}</li>
 *   <li>{@code if (c) goto E; a goto J; E: b J:} becomes {@code if (!c) { a } else { b }}</li>
 *   <li>backward jump {@code L: body if (c) goto L;} becomes {@code do { body } while (c);}
 *       ({@code goto L} alone becomes {@code } while (1);})</li>
 *   <li>{@code T: if (c) goto X; body goto T; X:} becomes {@code while (!c) { body }}</li>
 * </ul>
 * A shape is only rewritten when its labels are referenced exactly once, nothing jumps into the middle of it from
 * outside, and it nests cleanly with the shapes already accepted. Anything else stays a {@code goto}.
 * {@code break}/{@code continue} and loops with extra exits are deliberately not recognised.
 */
final class Structurer {

    /** One output line. {@code target}/{@code label} are branch addresses inside the function, else -1. */
    record Stmt(String text, String cond, String neg, long target, long label) {
        static Stmt plain(String text) { return new Stmt(text, null, null, -1, -1); }
        static Stmt label(long addr) { return new Stmt("L_" + Long.toHexString(addr) + ":", null, null, -1, addr); }
        static Stmt jump(String cond, String neg, long target) {
            String text = cond == null ? "goto L_" + Long.toHexString(target) + ";"
                    : "if (" + cond + ") goto L_" + Long.toHexString(target) + ";";
            return new Stmt(text, cond, neg, target, -1);
        }
        boolean isJump() { return target >= 0; }
        boolean isLabel() { return label >= 0; }
    }

    private enum Kind { SKIP, LOOP, IF_ELSE, WHILE }

    /**
     * @param open  first line of the block ({@code if}/{@code do}/{@code while})
     * @param mid   IF_ELSE: the {@code goto J} line that becomes {@code } else {}; WHILE: the exit test; else -1
     * @param close last line of the block
     * @param extra a label line the block absorbs (the else label / the loop exit label), else -1
     */
    private record Region(Kind kind, int open, int mid, int close, int extra) {
        /** Line ranges that must nest with every other block. */
        int[][] spans() {
            return kind == Kind.IF_ELSE ? new int[][] {{open, mid}, {mid, close}} : new int[][] {{open, close}};
        }
    }

    private Structurer() {}

    static String render(List<Stmt> s) {
        Map<Long, Integer> labelAt = new HashMap<>();
        Map<Long, List<Integer>> refs = new HashMap<>();
        for (int i = 0; i < s.size(); i++) {
            Stmt st = s.get(i);
            if (st.isLabel()) labelAt.put(st.label(), i);
            if (st.isJump()) refs.computeIfAbsent(st.target(), k -> new ArrayList<>()).add(i);
        }
        Ctx c = new Ctx(s, labelAt, refs);

        List<Region> accepted = new ArrayList<>();
        Set<Integer> used = new HashSet<>();
        // pass 1: shapes made of several jumps, before their parts are taken as plain skips/loops
        for (int i = 0; i < s.size(); i++) {
            Region r = whileLoop(c, i);
            if (r == null) r = ifElse(c, i);
            if (r != null) accept(r, c, accepted, used);
        }
        // pass 2: single skips and loops
        for (int i = 0; i < s.size(); i++) {
            Stmt st = s.get(i);
            if (!st.isJump() || used.contains(i)) continue;
            Integer j = labelAt.get(st.target());
            if (j == null || refs.get(st.target()).size() != 1 || used.contains(j)) continue;
            Region r;
            if (j > i) {
                if (st.cond() == null || st.neg() == null) continue;      // an unconditional forward goto has no block form
                r = new Region(Kind.SKIP, i, -1, j, -1);
            } else {
                r = new Region(Kind.LOOP, j, -1, i, -1);
            }
            accept(r, c, accepted, used);
        }

        String[] text = new String[s.size()];
        int[] closeBefore = new int[s.size()], openAfter = new int[s.size()];   // brace depth change around a line
        for (int i = 0; i < s.size(); i++) text[i] = s.get(i).text();
        for (Region r : accepted) {
            Stmt open = s.get(r.open()), close = s.get(r.close());
            switch (r.kind()) {
                case SKIP -> { text[r.open()] = "if (" + open.neg() + ") {"; text[r.close()] = "}"; }
                case LOOP -> {
                    text[r.open()] = "do {";
                    text[r.close()] = "} while (" + (close.cond() == null ? "1" : close.cond()) + ");";
                }
                case IF_ELSE -> {
                    text[r.open()] = "if (" + open.neg() + ") {";
                    text[r.mid()] = "} else {";
                    text[r.extra()] = "";
                    text[r.close()] = "}";
                    closeBefore[r.mid()]++;
                    openAfter[r.mid()]++;
                }
                case WHILE -> {
                    text[r.open()] = "while (" + s.get(r.mid()).neg() + ") {";
                    text[r.mid()] = "";
                    text[r.close()] = "}";
                    text[r.extra()] = "";
                }
            }
            openAfter[r.open()]++;
            closeBefore[r.close()]++;
        }

        StringBuilder out = new StringBuilder();
        int depth = 0;
        for (int i = 0; i < text.length; i++) {
            depth -= closeBefore[i];
            if (text[i].isEmpty()) out.append('\n');
            else out.append("  ".repeat(Math.max(0, depth))).append(text[i]).append('\n');
            depth += openAfter[i];
        }
        return out.toString();
    }

    private record Ctx(List<Stmt> s, Map<Long, Integer> labelAt, Map<Long, List<Integer>> refs) {
        boolean once(long label) { return refs.getOrDefault(label, List.of()).size() == 1; }
    }

    /** {@code T: if (c) goto X; body goto T; X:} with {@code i} the back-edge {@code goto T}. */
    private static Region whileLoop(Ctx c, int i) {
        Stmt back = c.s().get(i);
        if (!back.isJump() || back.cond() != null) return null;
        Integer top = c.labelAt().get(back.target());
        if (top == null || top >= i || !c.once(back.target()) || top + 1 >= i || i + 1 >= c.s().size()) return null;
        Stmt test = c.s().get(top + 1), exit = c.s().get(i + 1);
        if (!test.isJump() || test.cond() == null || test.neg() == null || !exit.isLabel() || exit.label() != test.target()
                || !c.once(exit.label())) return null;
        return new Region(Kind.WHILE, top, top + 1, i, i + 1);
    }

    /** {@code if (c) goto E; a goto J; E: b J:} with {@code i} the conditional jump. */
    private static Region ifElse(Ctx c, int i) {
        Stmt test = c.s().get(i);
        if (!test.isJump() || test.cond() == null || test.neg() == null) return null;
        Integer e = c.labelAt().get(test.target());
        if (e == null || e <= i + 1 || !c.once(test.target())) return null;
        Stmt skip = c.s().get(e - 1);
        if (!skip.isJump() || skip.cond() != null) return null;
        Integer end = c.labelAt().get(skip.target());
        if (end == null || end <= e || !c.once(skip.target())) return null;
        return new Region(Kind.IF_ELSE, i, e - 1, end, e);
    }

    private static boolean accept(Region r, Ctx c, List<Region> accepted, Set<Integer> used) {
        for (int line : new int[] {r.open(), r.mid(), r.close(), r.extra()})
            if (line >= 0 && used.contains(line)) return false;
        Set<Integer> absorbed = new HashSet<>();
        if (r.extra() >= 0) absorbed.add(r.extra());
        for (int[] span : r.spans())
            if (!isClosed(span, c, absorbed)) return false;
        for (int[] span : r.spans())
            for (Region a : accepted)
                for (int[] other : a.spans())
                    if (!nests(span, other)) return false;
        accepted.add(r);
        used.add(r.open());
        used.add(r.close());
        if (r.mid() >= 0) used.add(r.mid());
        if (r.extra() >= 0) used.add(r.extra());
        return true;
    }

    /** No label strictly inside the span (other than absorbed ones) is the target of a jump from outside it. */
    private static boolean isClosed(int[] span, Ctx c, Set<Integer> absorbed) {
        for (int m = span[0] + 1; m < span[1]; m++) {
            Stmt st = c.s().get(m);
            if (!st.isLabel() || absorbed.contains(m)) continue;
            for (int from : c.refs().getOrDefault(st.label(), List.of()))
                if (from < span[0] || from > span[1]) return false;
        }
        return true;
    }

    /** Spans must be disjoint or fully nested; a partial overlap cannot be written as braces. */
    private static boolean nests(int[] r, int[] a) {
        boolean disjoint = r[1] < a[0] || a[1] < r[0];
        boolean inside = a[0] < r[0] && r[1] < a[1];
        boolean contains = r[0] < a[0] && a[1] < r[1];
        return disjoint || inside || contains;
    }
}
