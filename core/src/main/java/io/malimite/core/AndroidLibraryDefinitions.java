package io.malimite.core;

import java.util.List;
import java.util.Locale;

/** Android / Kotlin / Google SDK package prefixes skipped during JADX ingest. */
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
        // strip leading "sources." or file suffix
        if (n.endsWith(".java")) n = n.substring(0, n.length() - 5);
        String lower = n.toLowerCase(Locale.ROOT);
        for (String p : SKIP_PREFIXES) {
            if (lower.startsWith(p) || lower.contains("." + p)) return true;
        }
        // R.java / BuildConfig noise
        if (lower.endsWith(".r") || lower.endsWith(".buildconfig")) return true;
        return false;
    }

    public static List<String> getSkipPrefixes() {
        return SKIP_PREFIXES;
    }
}
