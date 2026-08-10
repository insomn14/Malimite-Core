package io.mailmite.core;

import java.util.List;

/**
 * Lightweight identity for a binary being analyzed by {@link GhidraRunner}.
 * Replaces a hard dependency on {@link Macho} so Android ELF {@code .so} files
 * can share the same headless pipeline.
 */
public record BinaryIdentity(
        /** Value written to SqliteStore {@code ExecutableName} columns. */
        String executableName,
        boolean isSwift,
        /** When true, enable Ghidra's Objective-C analyzer (iOS Mach-O only). */
        boolean enableObjectiveCAnalyzer,
        /** Class-name prefixes treated as system libraries (skipped decomp bodies). */
        List<String> libraryPrefixes,
        /**
         * Optional parent-class prefix for ingested functions, e.g. {@code native:libfoo.so}.
         * When non-null, ParentClass becomes {@code prefix/originalClass}.
         */
        String classNamespacePrefix
) {
    public BinaryIdentity {
        if (executableName == null || executableName.isBlank())
            executableName = "binary";
        libraryPrefixes = libraryPrefixes == null ? List.of() : List.copyOf(libraryPrefixes);
    }

    public static BinaryIdentity fromMacho(Macho macho, List<String> iosLibraryPrefixes) {
        return new BinaryIdentity(
                macho.getMachoExecutableName(),
                macho.isSwift(),
                true,
                iosLibraryPrefixes,
                null);
    }

    /**
     * Android ELF native library: store under the APK applicationId, no ObjC analyzer,
     * namespace functions under {@code native:libFileName}.
     */
    public static BinaryIdentity forAndroidNativeLib(String applicationId, String libFileName) {
        String prefix = "native:" + (libFileName == null || libFileName.isBlank() ? "libunknown.so" : libFileName);
        return new BinaryIdentity(
                applicationId,
                false,
                false,
                AndroidNativeLibraryDefinitions.getSkipPrefixes(),
                prefix);
    }
}
