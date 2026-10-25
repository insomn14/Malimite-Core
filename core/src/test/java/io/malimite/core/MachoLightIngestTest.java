package io.malimite.core;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class MachoLightIngestTest {

    /** Thin arm64-style Mach-O with only LC_SYMTAB: one undefined external ("_strcpy"), one defined ("_main"). */
    private static byte[] tinyMacho() throws Exception {
        byte[] strtab = "\0_strcpy\0_main\0".getBytes(StandardCharsets.US_ASCII);
        int symoff = 32 + 24, stroff = symoff + 2 * 16;
        ByteBuffer b = ByteBuffer.allocate(stroff + strtab.length + 128).order(ByteOrder.LITTLE_ENDIAN);
        b.putInt(0xFEEDFACF).putInt(0x0100000C).putInt(0).putInt(2).putInt(1).putInt(24).putInt(0).putInt(0);
        b.putInt(2).putInt(24).putInt(symoff).putInt(2).putInt(stroff).putInt(strtab.length);
        b.putInt(1).put((byte) 0x01).put((byte) 0).putShort((short) 0).putLong(0);   // _strcpy: N_UNDF | N_EXT
        b.putInt(9).put((byte) 0x0F).put((byte) 1).putShort((short) 0).putLong(0x1000); // _main: N_SECT | N_EXT
        b.put(strtab);
        b.put("visible_text_in_cstring_section".getBytes(StandardCharsets.US_ASCII)).put((byte) 0);
        b.put("visible_text_in_cstring_section".getBytes(StandardCharsets.US_ASCII)).put((byte) 0);  // duplicate
        b.put("ab".getBytes(StandardCharsets.US_ASCII));                                              // too short
        return java.util.Arrays.copyOf(b.array(), b.position());
    }

    @Test
    void lightIngestReadsUniqueStringsAndOnlyImportedSymbols(@TempDir Path tmp) throws Exception {
        Path bin = tmp.resolve("App");
        Files.write(bin, tinyMacho());
        try (SqliteStore store = new SqliteStore(tmp.resolve("t.sqlite").toString())) {
            assertEquals(1, MachoLightIngest.ingestStrings(bin, store, "App"),
                    "strtab skipped, duplicate dropped, short run dropped");
            assertEquals("visible_text_in_cstring_section", store.getMachoStrings().get(0).get("value"));
            assertEquals(1, MachoLightIngest.ingestImports(bin, store, "App"));
            var fns = store.getAllDecompiledFunctions("App");
            assertEquals("_strcpy", fns.get(0).functionName());
        }
    }

    @Test
    void lightScanReportsEveryPseudocodeRuleAsNotEvaluated() {
        var ids = MalimiteAnalyzer.lightSkippedRuleIds();
        assertTrue(ids.contains("MSTG-STORAGE-2") && ids.contains("MASTG-TEST-0397"), ids.toString());
        assertTrue(ids.stream().noneMatch(i -> i.equals("MSTG-NETWORK-4")), "ABSENCE rules still run in light mode");
    }
}
