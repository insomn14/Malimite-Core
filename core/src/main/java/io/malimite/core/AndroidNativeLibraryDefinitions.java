package io.malimite.core;

import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Native library classification for Android {@code .so} files.
 *
 * <p>NDK system prefixes are skipped during Ghidra decompile bodies (same idea
 * as iOS {@link LibraryDefinitions}). Vendor names are skipped in first-party
 * scan scope before Ghidra is launched. Security-SDK names are re-included
 * for Offensive mode only.
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

    /**
     * Well-known third-party / vendor native libs. First-party scans skip these
     * before Ghidra. {@code conscrypt} is also on the Offensive security allowlist.
     */
    private static final List<String> VENDOR_MARKERS = List.of(
            "bugsnag",
            "objectbox",
            "conscrypt",
            "avif",
            "barhopper",
            "csgface",
            "finauth",
            "cashshield",
            "datastoreshared",
            "ndkcamera",
            "flutter",
            "reactnative",
            "hermes",
            "sqlcipher",
            "opencv",
            "ffmpeg",
            "libjxl",
            "libwebp",
            "libheif",
            "cronet",
            "crashlytics",
            "tensorflow",
            "tflite",
            "exoplayer",
            "lottie",
            "sentry"
    );

    /**
     * Narrow Offensive-only native allowlist: root/JB/Frida/RASP/pinning.
     * {@code toolChecker} is here (not on the vendor denylist) so Fast Scan
     * still skips it unless the name matches an app brand token.
     */
    private static final List<String> SECURITY_SDK_MARKERS = List.of(
            "toolchecker",
            "rootbeer",
            "appguard",
            "talsec",
            "freerasp",
            "promon",
            "conscrypt",
            "approov",
            "appdome",
            "nprotect",
            "dexguard"
    );

    private static final Set<String> GENERIC_APP_JNI_STEMS = Set.of(
            "native-lib",
            "nativelib",
            "native_lib",
            "native",
            "jni",
            "app",
            "main"
    );

    public static List<String> getSkipPrefixes() {
        return SKIP_PREFIXES;
    }

    public static boolean isNdkSystemLib(String soFileName) {
        if (soFileName == null || soFileName.isBlank()) return false;
        String n = soFileName.toLowerCase(Locale.ROOT);
        for (String p : SKIP_PREFIXES) {
            if (n.equals(p.toLowerCase(Locale.ROOT)) || n.endsWith("/" + p.toLowerCase(Locale.ROOT)))
                return true;
        }
        return false;
    }

    public static boolean isVendorLib(String soFileName) {
        return markerHit(stem(soFileName), VENDOR_MARKERS);
    }

    public static boolean isSecuritySdkLib(String soFileName) {
        return markerHit(stem(soFileName), SECURITY_SDK_MARKERS);
    }

    /** Typical Gradle JNI default {@code libnative-lib.so} and similar app-module names. */
    public static boolean isGenericAppJni(String soFileName) {
        String s = stem(soFileName);
        if (s.isEmpty()) return false;
        if (GENERIC_APP_JNI_STEMS.contains(s)) return true;
        String compact = s.replace("-", "").replace("_", "");
        return GENERIC_APP_JNI_STEMS.contains(compact);
    }

    /**
     * Lowercase library stem: {@code libFoo-Bar.so} → {@code foobar} (separators stripped
     * so {@code datastore_shared} and {@code ndkCamera} match).
     */
    public static String stem(String soFileName) {
        if (soFileName == null || soFileName.isBlank()) return "";
        String n = soFileName;
        int slash = Math.max(n.lastIndexOf('/'), n.lastIndexOf('\\'));
        if (slash >= 0) n = n.substring(slash + 1);
        n = n.toLowerCase(Locale.ROOT);
        if (n.endsWith(".so")) n = n.substring(0, n.length() - 3);
        if (n.startsWith("lib")) n = n.substring(3);
        return n.replace("-", "").replace("_", "").replace(".", "");
    }

    private static boolean markerHit(String compactStem, List<String> markers) {
        if (compactStem.isEmpty()) return false;
        for (String m : markers) {
            if (compactStem.contains(m)) return true;
        }
        return false;
    }
}
