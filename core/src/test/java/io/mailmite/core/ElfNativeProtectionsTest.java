package io.mailmite.core;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class ElfNativeProtectionsTest {

    @TempDir Path tmp;

    @Test void inspectDetectsDynCanaryAndDebug() throws Exception {
        Path so = tmp.resolve("libtest.so");
        Files.write(so, minimalElf(true, true, true));
        ElfNativeProtections.Report r = ElfNativeProtections.inspect(so);
        assertEquals("libtest.so", r.libName());
        assertTrue(r.picOrDyn());
        assertTrue(r.stackCanary());
        assertTrue(r.hasDebugInfo());
    }

    @Test void inspectFlagsExecWithoutCanary() throws Exception {
        Path so = tmp.resolve("libbad.so");
        Files.write(so, minimalElf(false, false, false));
        ElfNativeProtections.Report r = ElfNativeProtections.inspect(so);
        assertFalse(r.picOrDyn());
        assertFalse(r.stackCanary());
        assertFalse(r.hasDebugInfo());
    }

    @Test void ingestWritesDistinctResourceValues() throws Exception {
        Path so = tmp.resolve("libapp.so");
        Files.write(so, minimalElf(true, false, true));
        Path db = tmp.resolve("t.sqlite");
        try (SqliteStore store = new SqliteStore(db.toString())) {
            ElfNativeProtections.ingest(store, so);
            List<Map<String, String>> res = store.getResourceStrings();
            assertTrue(res.stream().anyMatch(m ->
                    m.get("value").equals("NativeLibPic=libapp.so=enabled")));
            assertTrue(res.stream().anyMatch(m ->
                    m.get("value").equals("NativeLibStackCanary=libapp.so=disabled")));
            assertTrue(res.stream().anyMatch(m ->
                    m.get("value").equals("NativeLibDebugSymbols=libapp.so=present")));
        }
    }

    /** Tiny ELF64 LE with configurable e_type and trailing ASCII markers. */
    static byte[] minimalElf(boolean dyn, boolean canary, boolean debug) {
        byte[] header = new byte[64];
        header[0] = 0x7f;
        header[1] = 'E';
        header[2] = 'L';
        header[3] = 'F';
        header[4] = 2; // ELFCLASS64
        header[5] = 1; // little endian
        header[6] = 1;
        ByteBuffer.wrap(header).order(ByteOrder.LITTLE_ENDIAN)
                .putShort(16, (short) (dyn ? ElfNativeProtections.ET_DYN : ElfNativeProtections.ET_EXEC));
        StringBuilder tail = new StringBuilder();
        if (canary) tail.append("__stack_chk_fail\0");
        if (debug) tail.append(".debug_info\0");
        tail.append("padding");
        byte[] t = tail.toString().getBytes(StandardCharsets.US_ASCII);
        byte[] out = new byte[header.length + t.length];
        System.arraycopy(header, 0, out, 0, header.length);
        System.arraycopy(t, 0, out, header.length, t.length);
        return out;
    }
}
