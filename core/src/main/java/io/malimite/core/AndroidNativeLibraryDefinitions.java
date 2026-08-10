package io.malimite.core;

import java.util.List;

/**
 * Class-name / namespace prefixes for Android NDK system libraries whose
 * decompiled bodies are skipped during Ghidra ingest (similar to iOS
 * {@link LibraryDefinitions}).
 */
public final class AndroidNativeLibraryDefinitions {

    private AndroidNativeLibraryDefinitions() {}

    private static final List<String> SKIP_PREFIXES = List.of(
            "libc.so",
            "libm.so",
            "libdl.so",
            "liblog.so",
            "libandroid.so",
            "libjnigraphics.so",
            "libEGL.so",
            "libGLESv2.so",
            "libGLESv3.so",
            "libOpenSLES.so",
            "libz.so",
            "libstdc++.so"
    );

    public static List<String> getSkipPrefixes() {
        return SKIP_PREFIXES;
    }
}
