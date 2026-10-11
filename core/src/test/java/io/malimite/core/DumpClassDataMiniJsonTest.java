package io.malimite.core;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.tools.JavaCompiler;
import javax.tools.ToolProvider;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

/**
 * DumpClassData runs inside Ghidra, where no third-party jar is on the script compile classpath (org.json was
 * "package org.json does not exist" on Ghidra 12.0.4). It therefore carries its own JSON writer. We cannot run
 * the Ghidra script here, so compile just that block and parse its output with the real org.json that
 * GhidraRunner uses on the receiving side.
 */
class DumpClassDataMiniJsonTest {

    @TempDir Path tmp;

    private static String script() throws Exception {
        try (InputStream in = DumpClassDataMiniJsonTest.class.getResourceAsStream("/ghidra/DumpClassData.java")) {
            assertNotNull(in);
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    @Test
    void scriptHasNoThirdPartyImports() throws Exception {
        assertFalse(script().contains("import org.json"), "Ghidra cannot compile against org.json");
    }

    private Class<?> compileHarness(String body) throws Exception {
        String src = script();
        String block = src.substring(src.indexOf("// BEGIN MINIJSON"), src.indexOf("// END MINIJSON"));
        Path file = tmp.resolve("Harness.java");
        Files.writeString(file, "import java.util.*;\npublic class Harness {\n" + block + "\n" + body + "\n}\n");
        JavaCompiler jc = ToolProvider.getSystemJavaCompiler();
        assertNotNull(jc, "tests need a JDK");
        assertEquals(0, jc.run(null, null, null, "-d", tmp.toString(), file.toString()), "harness must compile");
        return new URLClassLoader(new java.net.URL[] {tmp.toUri().toURL()}).loadClass("Harness");
    }

    @Test
    void outputRoundTripsThroughOrgJsonIncludingNastyStrings() throws Exception {
        Class<?> h = compileHarness("""
                public static String sample(String nasty) {
                    JSONArray out = new JSONArray();
                    JSONObject e = new JSONObject();
                    e.put("FunctionName", "-[Foo bar:]");
                    e.put("DecompiledCode", nasty);
                    e.put("n", 42);
                    e.put("ok", true);
                    e.put("skipped", null);                       // org.json semantics: key is dropped
                    out.put(e);
                    out.put(new JSONObject(Map.of("k", "v")));
                    out.put(new JSONArray(List.of("a", "b")));
                    return out.toString(4) + "|" + out.length();
                }
                """);
        Method m = h.getMethod("sample", String.class);
        String nasty = "q\" b\\ nl\n cr\r tab\t bs\b ff\f \u0001 \u001f é中😀 </script>    {\"a\":[1]}";
        String[] parts = ((String) m.invoke(null, nasty)).split("\\|");
        assertEquals("3", parts[1]);
        JSONArray parsed = new JSONArray(parts[0]);             // the receiver's parser
        JSONObject e = parsed.getJSONObject(0);
        assertEquals(nasty, e.getString("DecompiledCode"));
        assertEquals("-[Foo bar:]", e.getString("FunctionName"));
        assertEquals(42, e.getInt("n"));
        assertTrue(e.getBoolean("ok"));
        assertFalse(e.has("skipped"));
        assertEquals("v", parsed.getJSONObject(1).getString("k"));
        assertEquals("b", parsed.getJSONArray(2).getString(1));
        assertFalse(parts[0].contains("\n"), "must stay on one line: the receiver reads line by line to a terminator");
    }

    @Test
    void emptyContainersAndLargeOutputParse() throws Exception {
        Class<?> h = compileHarness("""
                public static String empty() { return new JSONArray().toString() + new JSONObject().toString(); }
                public static String big(int n) {
                    JSONArray a = new JSONArray();
                    for (int i = 0; i < n; i++) a.put(new JSONObject().put("i", i).put("s", "x".repeat(50)));
                    return a.toString(4);
                }
                """);
        assertEquals("[]{}", h.getMethod("empty").invoke(null));
        JSONArray a = new JSONArray((String) h.getMethod("big", int.class).invoke(null, 20000));
        assertEquals(20000, a.length());
        assertEquals(19999, a.getJSONObject(19999).getInt("i"));
    }
}
