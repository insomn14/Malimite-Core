package io.malimite.core;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Lightweight ELF inspection for Android {@code .so} binary protections
 * (PIC/DYN, stack canaries, DWARF debug sections) without requiring readelf.
 */
public final class ElfNativeProtections {

    private static final Logger log = LoggerFactory.getLogger(ElfNativeProtections.class);

    /** ELF e_type: shared object / PIE-capable dynamic object. */
    static final int ET_DYN = 3;
    static final int ET_EXEC = 2;

    private ElfNativeProtections() {}

    public record Report(
            String libName,
            boolean picOrDyn,
            boolean stackCanary,
            boolean hasDebugInfo
    ) {}

    public static Report inspect(Path soPath) throws IOException {
        String libName = soPath.getFileName().toString();
        byte[] data = Files.readAllBytes(soPath);
        if (data.length < 64 || data[0] != 0x7f || data[1] != 'E' || data[2] != 'L' || data[3] != 'F') {
            log.warn("Not a valid ELF: {}", soPath);
            return new Report(libName, false, false, false);
        }

        boolean little = (data[5] == 1);
        boolean is64 = (data[4] == 2);
        ByteBuffer buf = ByteBuffer.wrap(data).order(little ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN);
        int eType = Short.toUnsignedInt(buf.getShort(16));
        boolean picOrDyn = (eType == ET_DYN);

        boolean stackCanary = containsAscii(data, "__stack_chk_fail")
                || containsAscii(data, "stack_chk_fail");
        boolean hasDebugInfo = containsAscii(data, ".debug_info")
                || containsAscii(data, ".debug_line")
                || containsAscii(data, ".debug_str");

        // Prefer section-header name scan when headers look sane
        try {
            if (scanSectionNames(buf, is64, data).contains(".debug_info"))
                hasDebugInfo = true;
        } catch (Exception e) {
            log.debug("ELF section scan failed for {}: {}", libName, e.getMessage());
        }

        return new Report(libName, picOrDyn, stackCanary, hasDebugInfo);
    }

    /**
     * Writes {@code NativeLib*} resource rows consumed by Android MASTG RESOURCES rules.
     */
    public static void ingest(SqliteStore store, Path soPath) {
        try {
            Report r = inspect(soPath);
            // Value includes the key so RESOURCES regexes can distinguish flag types.
            store.insertResourceString(
                    "NativeLibPic",
                    "NativeLibPic=" + r.libName() + "=" + (r.picOrDyn() ? "enabled" : "disabled"),
                    "native-elf");
            store.insertResourceString(
                    "NativeLibStackCanary",
                    "NativeLibStackCanary=" + r.libName() + "="
                            + (r.stackCanary() ? "enabled" : "disabled"),
                    "native-elf");
            store.insertResourceString(
                    "NativeLibDebugSymbols",
                    "NativeLibDebugSymbols=" + r.libName() + "="
                            + (r.hasDebugInfo() ? "present" : "stripped"),
                    "native-elf");
            log.info("ELF protections {}: pic={} canary={} debug={}",
                    r.libName(), r.picOrDyn(), r.stackCanary(), r.hasDebugInfo());
        } catch (Exception e) {
            log.warn("ELF inspect failed for {}: {}", soPath, e.getMessage());
        }
    }

    static boolean containsAscii(byte[] data, String needle) {
        byte[] n = needle.getBytes(StandardCharsets.US_ASCII);
        outer:
        for (int i = 0; i <= data.length - n.length; i++) {
            for (int j = 0; j < n.length; j++) {
                if (data[i + j] != n[j]) continue outer;
            }
            return true;
        }
        return false;
    }

    /** Collect section names from the string table referenced by the section header table. */
    static String scanSectionNames(ByteBuffer buf, boolean is64, byte[] data) {
        long eShOff;
        int eShEntSize;
        int eShNum;
        int eShStrNdx;
        if (is64) {
            eShOff = buf.getLong(40);
            eShEntSize = Short.toUnsignedInt(buf.getShort(58));
            eShNum = Short.toUnsignedInt(buf.getShort(60));
            eShStrNdx = Short.toUnsignedInt(buf.getShort(62));
        } else {
            eShOff = Integer.toUnsignedLong(buf.getInt(32));
            eShEntSize = Short.toUnsignedInt(buf.getShort(46));
            eShNum = Short.toUnsignedInt(buf.getShort(48));
            eShStrNdx = Short.toUnsignedInt(buf.getShort(50));
        }
        if (eShOff <= 0 || eShNum <= 0 || eShEntSize <= 0 || eShStrNdx >= eShNum) return "";
        long strOff;
        long strSize;
        int strHdr = (int) (eShOff + (long) eShStrNdx * eShEntSize);
        if (strHdr + (is64 ? 40 : 24) > data.length) return "";
        if (is64) {
            strOff = buf.getLong(strHdr + 24);
            strSize = buf.getLong(strHdr + 32);
        } else {
            strOff = Integer.toUnsignedLong(buf.getInt(strHdr + 16));
            strSize = Integer.toUnsignedLong(buf.getInt(strHdr + 20));
        }
        if (strOff < 0 || strSize <= 0 || strOff + strSize > data.length) return "";
        return new String(data, (int) strOff, (int) strSize, StandardCharsets.ISO_8859_1);
    }
}
