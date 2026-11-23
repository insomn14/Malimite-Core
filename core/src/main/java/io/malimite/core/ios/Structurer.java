package io.malimite.core.ios;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Turns the two goto shapes compilers emit most into blocks, one output line per input line (so the line numbers the
 * lifter recorded for {@code FunctionReferences} stay valid):
 * <ul>
 *   <li>forward skip {@code if (c) goto L; body L:} becomes {@code if (!c) { body }}</li>
 *   <li>backward jump {@code L: body if (c) goto L;} becomes {@code do { body } while (c);}
 *       ({@code goto L} alone becomes {@code } while (1);})</li>
 * </ul>
 * A shape is only rewritten when its label is referenced exactly once, nothing jumps into the middle of it from outside,
 * and it nests cleanly with the shapes already accepted. Anything else stays a {@code goto}. If/else, {@code while}
 * with the test on top and {@code break}/{@code continue} are deliberately not recognised.
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

    private enum Kind { SKIP, LOOP }

    /** Rewrite {@code open}..{@code close} (statement indexes) as a block. */
    private record Region(Kind kind, int open, int close) {}

    private Structurer() {}

    static String render(List<Stmt> s) {
        Map<Long, Integer> labelAt = new HashMap<>();
        Map<Long, List<Integer>> refs = new HashMap<>();
        for (int i = 0; i < s.size(); i++) {
            Stmt st = s.get(i);
            if (st.isLabel()) labelAt.put(st.label(), i);
            if (st.isJump()) refs.computeIfAbsent(st.target(), k -> new ArrayList<>()).add(i);
        }

        List<Region> accepted = new ArrayList<>();
        for (int i = 0; i < s.size(); i++) {
            Stmt st = s.get(i);
            if (!st.isJump()) continue;
            Integer j = labelAt.get(st.target());
            if (j == null || refs.get(st.target()).size() != 1) continue;
            Region r;
            if (j > i) {
                if (st.cond() == null || st.neg() == null) continue;      // an unconditional forward goto has no block form
                r = new Region(Kind.SKIP, i, j);
            } else {
                r = new Region(Kind.LOOP, j, i);
            }
            if (isClosed(r, s, labelAt, refs) && nestsWith(r, accepted)) accepted.add(r);
        }

        String[] text = new String[s.size()];
        int[] depthDelta = new int[s.size()];   // +1 after an opening line, -1 before a closing one
        for (int i = 0; i < s.size(); i++) text[i] = s.get(i).text();
        for (Region r : accepted) {
            Stmt open = s.get(r.open()), close = s.get(r.close());
            if (r.kind() == Kind.SKIP) {
                text[r.open()] = "if (" + open.neg() + ") {";
                text[r.close()] = "}";
            } else {
                text[r.open()] = "do {";
                text[r.close()] = "} while (" + (close.cond() == null ? "1" : close.cond()) + ");";
            }
            depthDelta[r.open()] = 1;
            depthDelta[r.close()] = -1;
        }

        StringBuilder out = new StringBuilder();
        int depth = 0;
        for (int i = 0; i < text.length; i++) {
            if (depthDelta[i] < 0) depth--;
            out.append("  ".repeat(Math.max(0, depth))).append(text[i]).append('\n');
            if (depthDelta[i] > 0) depth++;
        }
        return out.toString();
    }

    /** No label strictly inside the region is the target of a jump from outside it (that would enter the block). */
    private static boolean isClosed(Region r, List<Stmt> s, Map<Long, Integer> labelAt, Map<Long, List<Integer>> refs) {
        for (int m = r.open() + 1; m < r.close(); m++) {
            Stmt st = s.get(m);
            if (!st.isLabel()) continue;
            for (int from : refs.getOrDefault(st.label(), List.of()))
                if (from < r.open() || from > r.close()) return false;
        }
        return true;
    }

    /** Regions must be disjoint or fully nested; a partial overlap cannot be written as braces. */
    private static boolean nestsWith(Region r, List<Region> accepted) {
        for (Region a : accepted) {
            boolean disjoint = r.close() < a.open() || a.close() < r.open();
            boolean inside = a.open() < r.open() && r.close() < a.close();
            boolean contains = r.open() < a.open() && a.close() < r.close();
            if (!(disjoint || inside || contains)) return false;
        }
        return true;
    }
}
