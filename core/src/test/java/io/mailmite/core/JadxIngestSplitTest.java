package io.mailmite.core;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JadxIngestSplitTest {

    @Test
    void methodSplitExtractsNormalMethods() {
        String code = """
                package com.example;
                public class Foo {
                  public void alpha() {
                    System.out.println("a");
                  }
                  private static final int beta(int x) throws Exception {
                    return x + 1;
                  }
                  protected <T> T gamma(T t) {
                    return t;
                  }
                }
                """;
        var methods = JadxIngest.splitMethods(code);
        assertTrue(methods.stream().anyMatch(m -> m.name().equals("alpha")));
        assertTrue(methods.stream().anyMatch(m -> m.name().equals("beta")));
        assertTrue(methods.stream().anyMatch(m -> m.name().equals("gamma")));
    }

    @Test
    @Timeout(value = 5, unit = TimeUnit.SECONDS)
    void pathologicalModifierRunsDoNotStackOverflow() {
        // Long runs of modifier-like tokens previously triggered catastrophic backtracking
        // via nested (?:(?:modifiers)[ \\t]+)* on truncated JADX output.
        String modifiers = IntStream.range(0, 8_000)
                .mapToObj(i -> "public static final native synchronized abstract default strictfp ")
                .collect(Collectors.joining());
        String code = """
                package com.example;
                public class Synthetic {
                %s
                  int field;
                }
                """.formatted(modifiers);

        var methods = JadxIngest.splitMethods(code);
        assertEquals(0, methods.size());
    }

    @Test
    @Timeout(value = 5, unit = TimeUnit.SECONDS)
    void largeSyntheticJavaCompletesSafely() {
        StringBuilder sb = new StringBuilder(120_000);
        sb.append("package com.example;\npublic class Huge {\n");
        for (int i = 0; i < 2_000; i++) {
            sb.append("  public static final String C").append(i)
                    .append(" = \"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\";\n");
        }
        // Trailing modifier soup without a closing method — classic backtracking bait.
        sb.append("  public protected private static final native synchronized abstract ");
        sb.append("default strictfp public static final ");
        sb.append(IntStream.range(0, 3_000)
                .mapToObj(i -> "static final ")
                .collect(Collectors.joining()));
        sb.append("\n}\n");

        var methods = JadxIngest.splitMethods(sb.toString());
        assertTrue(methods.size() >= 0); // empty or partial OK; must not throw
    }

    @Test
    void lowValueGeneratedClassesDetected() {
        assertTrue(JadxIngest.isLowValueGenerated("R"));
        assertTrue(JadxIngest.isLowValueGenerated("R$id"));
        assertTrue(JadxIngest.isLowValueGenerated("R$layout"));
        assertTrue(JadxIngest.isLowValueGenerated("BuildConfig"));
        assertFalse(JadxIngest.isLowValueGenerated("MainActivity"));
        assertFalse(JadxIngest.isLowValueGenerated("Router"));
    }

    @Test
    void extractStringLiteralsHandlesEscapes() {
        String code = "String a = \"hello\"; String b = \"ab\\\"cd\"; String c = \"ab\";";
        var lits = JadxIngest.extractStringLiterals(code, 50);
        assertTrue(lits.contains("hello"));
        assertTrue(lits.contains("ab\"cd")); // escaped quote, length >= 4
        assertFalse(lits.contains("ab")); // length < 4 filtered
    }

    @Test
    @Timeout(value = 5, unit = TimeUnit.SECONDS)
    void truncatedUnclosedStringDoesNotStackOverflow() {
        // Previous Pattern STRING_LIT ("((?:\\.|[^"\\])*)") StackOverflowed here
        // (Branch+Loop+CharProperty) when JADX truncation cut mid-literal.
        StringBuilder sb = new StringBuilder(60_000);
        sb.append("class X {\n  String s = \"");
        for (int i = 0; i < 40_000; i++) sb.append('\\');
        sb.append("\n  // truncated\n}\n");
        var lits = JadxIngest.extractStringLiterals(sb.toString(), 100);
        assertEquals(0, lits.size());
    }

    @Test
    @Timeout(value = 5, unit = TimeUnit.SECONDS)
    void longClosedStringDoesNotStackOverflow() {
        StringBuilder sb = new StringBuilder(90_000);
        sb.append('"');
        for (int i = 0; i < 80_000; i++) sb.append('a');
        sb.append('"');
        var lits = JadxIngest.extractStringLiterals(sb.toString(), 10);
        // Oversized literal (> MAX_STRING_LIT_CHARS) is abandoned — must not throw.
        assertEquals(0, lits.size());
    }
}
