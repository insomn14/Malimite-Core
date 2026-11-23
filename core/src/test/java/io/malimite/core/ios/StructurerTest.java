package io.malimite.core.ios;

import io.malimite.core.ios.Structurer.Stmt;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class StructurerTest {

    private static Stmt p(String s) { return Stmt.plain(s); }
    private static Stmt skip(long to) { return Stmt.jump("x0 == 0", "x0 != 0", to); }

    @Test
    void forwardSkipBecomesIfBlockAndKeepsLineCount() {
        String out = Structurer.render(List.of(skip(0x20), p("NSLog(\"a\");"), Stmt.label(0x20), p("return;")));
        assertEquals("if (x0 != 0) {\n  NSLog(\"a\");\n}\nreturn;\n", out);
        assertEquals(4, out.split("\n").length);
    }

    @Test
    void backwardConditionalJumpBecomesDoWhile() {
        String out = Structurer.render(List.of(Stmt.label(0x10), p("foo();"), Stmt.jump("x1 != 0", "x1 == 0", 0x10), p("return;")));
        assertEquals("do {\n  foo();\n} while (x1 != 0);\nreturn;\n", out);
    }

    @Test
    void backwardUnconditionalJumpBecomesInfiniteLoop() {
        String out = Structurer.render(List.of(Stmt.label(0x10), p("poll();"), Stmt.jump(null, null, 0x10)));
        assertEquals("do {\n  poll();\n} while (1);\n", out);
    }

    @Test
    void nestedShapesIndent() {
        String out = Structurer.render(List.of(
                skip(0x40), Stmt.label(0x10), p("work();"), Stmt.jump("x2 != 0", "x2 == 0", 0x10), Stmt.label(0x40), p("return;")));
        assertEquals("if (x0 != 0) {\n  do {\n    work();\n  } while (x2 != 0);\n}\nreturn;\n", out);
    }

    @Test
    void labelWithTwoReferencesStaysAGoto() {
        List<Stmt> s = List.of(skip(0x20), p("a();"), skip(0x20), p("b();"), Stmt.label(0x20), p("return;"));
        assertEquals("if (x0 == 0) goto L_20;\na();\nif (x0 == 0) goto L_20;\nb();\nL_20:\nreturn;\n", Structurer.render(s));
    }

    @Test
    void jumpIntoTheMiddleOfABlockIsNotStructured() {
        // the forward skip would swallow L_30, which a later backward jump re-enters; and that loop would swallow L_50
        List<Stmt> s = List.of(skip(0x50), p("a();"), Stmt.label(0x30), p("b();"), Stmt.label(0x50), Stmt.jump("x3 != 0", "x3 == 0", 0x30));
        assertEquals("if (x0 == 0) goto L_50;\na();\nL_30:\nb();\nL_50:\nif (x3 != 0) goto L_30;\n", Structurer.render(s));
    }

    @Test
    void partiallyOverlappingShapesKeepTheLaterOneAsGoto() {
        // A: 0..2  B: 1..3 overlap without nesting, only the first can become a block
        List<Stmt> s = List.of(skip(0x20), Stmt.jump("x1 == 0", "x1 != 0", 0x30), Stmt.label(0x20), p("a();"), Stmt.label(0x30), p("return;"));
        String out = Structurer.render(s);
        assertEquals(true, out.startsWith("if (x0 != 0) {\n"));
        assertEquals(true, out.contains("goto L_30;"));
    }

    @Test
    void forwardGotoWithoutNegationIsLeftAlone() {
        String out = Structurer.render(List.of(Stmt.jump("flags.x", null, 0x20), p("a();"), Stmt.label(0x20)));
        assertEquals("if (flags.x) goto L_20;\na();\nL_20:\n", out);
    }
}
