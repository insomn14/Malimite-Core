package io.malimite.core;

import java.util.List;
import java.util.Locale;

/**
 * Android / Kotlin / Google SDK package prefixes skipped during JADX ingest.
 *
 * <p>Matching is prefix-only ({@code startsWith}), not a substring search, so
 * first-party packages such as {@code com.example.foo.staging} are not treated
 * as the Android framework.
 */
public final class AndroidLibraryDefinitions {

    private AndroidLibraryDefinitions() {}

    private static final List<String> SKIP_PREFIXES = List.of(
            "android.",
            "androidx.",
            "com.google.",
            "com.android.",
            "kotlin.",
            "kotlinx.",
            "dalvik.",
            "java.",
            "javax.",
            "org.jetbrains.",
            "org.intellij.",
            "org.apache.",
            "okhttp3.",
            "okio.",
            "retrofit2.",
            "com.squareup.",
            "io.reactivex.",
            "reactor.",
            "dagger.",
            "javax.inject.",
            "com.fasterxml.",
            "org.json.",
            "org.xmlpull.",
            "org.w3c.",
            "org.xml."
    );

    public static boolean shouldSkip(String fqcnOrPath) {
        if (fqcnOrPath == null || fqcnOrPath.isBlank()) return true;
        String n = fqcnOrPath.replace('/', '.').replace('\\', '.');
        if (n.endsWith(".java")) n = n.substring(0, n.length() - 5);
        while (n.startsWith(".")) n = n.substring(1);
        String lower = n.toLowerCase(Locale.ROOT);
        if (lower.startsWith("sources."))
            lower = lower.substring("sources.".length());
        for (String p : SKIP_PREFIXES) {
            if (lower.startsWith(p)) return true;
        }
        // R.java / BuildConfig noise
        if (lower.endsWith(".r") || lower.endsWith(".buildconfig")) return true;
        return false;
    }

    public static List<String> getSkipPrefixes() {
        return SKIP_PREFIXES;
    }
}
