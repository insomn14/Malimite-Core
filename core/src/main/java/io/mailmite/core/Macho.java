package io.mailmite.core;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

/**
 * Parses Mach-O and Universal binary headers; detects architecture and Swift/ObjC language.
 * Port of Malimite's Macho.java — Swing/GUI removed.
 */
public class Macho {

    private static final Logger log = LoggerFactory.getLogger(Macho.class);

    private static final int UNIVERSAL_MAGIC = 0xcafebabe;
    private static final int UNIVERSAL_CIGAM = 0xbebafeca;
    private static final int MH_MAGIC_64     = 0xfeedfacf;
    private static final int MH_CIGAM_64     = 0xcffaedfe;
    private static final int MH_MAGIC        = 0xfeedface;
    private static final int MH_CIGAM        = 0xcefaedfe;
    /** MH_PIE — ASLR / position-independent executable flag. */
    private static final int MH_PIE_FLAG     = 0x00200000;

    private final List<Integer> cpuTypes    = new ArrayList<>();
    private final List<Integer> cpuSubTypes = new ArrayList<>();
    private final List<Long>    offsets     = new ArrayList<>();
    private final List<Long>    sizes       = new ArrayList<>();

    private boolean isUniversal;
    private boolean isSwift;
    /** null = unknown / unreadable header; otherwise whether MH_PIE is set. */
    private Boolean pieEnabled;
    private String  machoExecutablePath;
    private String  outputDirectoryPath;
    private String  machoExecutableName;

    public Macho(String machoExecutablePath, String outputDirectoryPath, String machoExecutableName) {
        this.machoExecutablePath  = machoExecutablePath;
        this.outputDirectoryPath  = outputDirectoryPath;
        this.machoExecutableName  = machoExecutableName;
        processMacho();
    }

    // ── Universal binary handling ─────────────────────────────────────────────

    public void processUniversalMacho(String selectedArchitecture) {
        extractMachoArchitecture(selectedArchitecture);
        processMacho(); // re-read after extraction
    }

    private void extractMachoArchitecture(String selectedArchitecture) {
        for (int i = 0; i < cpuTypes.size(); i++) {
            String arch = cpuTypeName(cpuTypes.get(i));
            String full = fullArchString(arch, cpuTypes.get(i), cpuSubTypes.get(i));
            if (!full.equals(selectedArchitecture)) continue;

            String tmpName = machoExecutableName + "_extracted.macho";
            try {
                extractSlice(machoExecutablePath, tmpName, offsets.get(i), sizes.get(i));
                replaceWithExtracted(tmpName);
                log.info("Extracted {} slice to {}", arch, tmpName);
            } catch (IOException e) {
                log.error("Error extracting Mach-O slice", e);
            }
            break;
        }
    }

    private void extractSlice(String inputPath, String outputName, long offset, long size) throws IOException {
        Path out = Paths.get(outputDirectoryPath, outputName);
        try (RandomAccessFile raf = new RandomAccessFile(inputPath, "r");
             FileOutputStream fos = new FileOutputStream(out.toFile())) {
            raf.seek(offset);
            byte[] buf = new byte[8192];
            long remaining = size;
            while (remaining > 0) {
                int read = raf.read(buf, 0, (int) Math.min(buf.length, remaining));
                if (read == -1) break;
                fos.write(buf, 0, read);
                remaining -= read;
            }
        }
    }

    private void replaceWithExtracted(String tmpName) throws IOException {
        Path old  = Paths.get(machoExecutablePath);
        Path tmp  = Paths.get(outputDirectoryPath, tmpName);
        Files.delete(old);
        Files.move(tmp, old);
        log.info("Replaced original Mach-O with extracted slice");
    }

    // ── Mach-O parsing ────────────────────────────────────────────────────────

    private void processMacho() {
        cpuTypes.clear(); cpuSubTypes.clear(); offsets.clear(); sizes.clear();
        try (RandomAccessFile raf = new RandomAccessFile(machoExecutablePath, "r")) {
            int magic = raf.readInt();
            if (magic == UNIVERSAL_MAGIC || magic == UNIVERSAL_CIGAM) {
                isUniversal = true;
                boolean swap = (magic == UNIVERSAL_CIGAM);
                int count = swap ? Integer.reverseBytes(raf.readInt()) : raf.readInt();
                for (int i = 0; i < count; i++) {
                    raf.seek(8L + i * 20L);
                    int cpu    = swap ? Integer.reverseBytes(raf.readInt()) : raf.readInt();
                    int subCpu = swap ? Integer.reverseBytes(raf.readInt()) : raf.readInt();
                    long off   = swap ? Integer.reverseBytes(raf.readInt()) : raf.readInt();
                    long sz    = swap ? Integer.reverseBytes(raf.readInt()) : raf.readInt();
                    cpuTypes.add(cpu); cpuSubTypes.add(subCpu);
                    offsets.add(off);  sizes.add(sz);
                }
                log.info("Universal binary detected with {} slice(s)", count);
            } else {
                isUniversal = false;
                log.info("Single-architecture Mach-O detected");
            }
            detectSwift();
            detectPie();
        } catch (IOException e) {
            log.error("Error reading Mach-O file: {}", machoExecutablePath, e);
        }
    }

    /**
     * Reads the Mach-O header {@code flags} field and records whether {@code MH_PIE} is set.
     * Defaults to {@code true} (do not false-positive) when the header cannot be parsed.
     */
    private void detectPie() {
        try (RandomAccessFile raf = new RandomAccessFile(machoExecutablePath, "r")) {
            int magic = raf.readInt();
            boolean swap;
            if (magic == MH_MAGIC_64 || magic == MH_MAGIC) {
                swap = false;
            } else if (magic == MH_CIGAM_64 || magic == MH_CIGAM) {
                swap = true;
            } else {
                pieEnabled = Boolean.TRUE;
                log.debug("Unknown Mach-O magic 0x{}; assuming PIE present", Integer.toHexString(magic));
                return;
            }
            // flags is at offset 24 for both 32-bit and 64-bit Mach-O headers
            raf.seek(24);
            int flags = raf.readInt();
            if (swap) flags = Integer.reverseBytes(flags);
            pieEnabled = (flags & MH_PIE_FLAG) != 0;
            log.info("Mach-O MH_PIE: {}", pieEnabled);
        } catch (IOException e) {
            log.warn("Could not read Mach-O PIE flag: {}", e.getMessage());
            pieEnabled = Boolean.TRUE;
        }
    }

    private void detectSwift() {
        try {
            byte[] content = Files.readAllBytes(Paths.get(machoExecutablePath));
            String text = new String(content, StandardCharsets.UTF_8);
            isSwift = text.contains("Swift Runtime") || text.contains("SwiftCore")
                   || text.contains("_swift_")       || text.contains("_$s");
            log.info("Language detected: {}", isSwift ? "Swift" : "Objective-C");
        } catch (IOException e) {
            log.warn("Could not determine Swift/ObjC language", e);
            isSwift = false;
        }
    }

    // ── Architecture helpers ──────────────────────────────────────────────────

    public record Architecture(String name, int cpuType, int cpuSubType) {
        @Override public String toString() {
            return name + " (CPU Type: " + cpuType + ", SubType: " + cpuSubType + ")";
        }
    }

    private String cpuTypeName(int cpuType) {
        return switch (cpuType) {
            case 0x00000007 -> "Intel x86";
            case 0x01000007 -> "Intel x86_64";
            case 0x0000000C -> "ARM";
            case 0x0100000C -> "ARM64";
            default         -> "Unknown";
        };
    }

    private String fullArchString(String arch, int cpuType, int cpuSubType) {
        return arch + " (CPU Type: " + cpuType + ", SubType: " + cpuSubType + ")";
    }

    public List<Architecture> getArchitectures() {
        List<Architecture> out = new ArrayList<>();
        for (int i = 0; i < cpuTypes.size(); i++)
            out.add(new Architecture(cpuTypeName(cpuTypes.get(i)), cpuTypes.get(i), cpuSubTypes.get(i)));
        return out;
    }

    public List<String> getArchitectureStrings() {
        List<String> out = new ArrayList<>();
        for (int i = 0; i < cpuTypes.size(); i++)
            out.add(fullArchString(cpuTypeName(cpuTypes.get(i)), cpuTypes.get(i), cpuSubTypes.get(i)));
        return out;
    }

    // ── Accessors ─────────────────────────────────────────────────────────────

    public boolean isUniversalBinary()    { return isUniversal; }
    public boolean isSwift()              { return isSwift; }
    /** Whether the thin Mach-O has {@code MH_PIE} set. Unknown headers are treated as enabled. */
    public boolean hasPie()               { return pieEnabled == null || pieEnabled; }
    public String  getMachoExecutableName() { return machoExecutableName; }
    public long    getSize()              { return Paths.get(machoExecutablePath).toFile().length(); }
    public List<Integer> getCpuTypes()    { return cpuTypes; }
    public List<Integer> getCpuSubTypes() { return cpuSubTypes; }
}
