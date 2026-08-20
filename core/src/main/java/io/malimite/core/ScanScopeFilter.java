package io.malimite.core;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Applies {@link ScanScope} to Java/Kotlin classes, iOS classes, and Android
 * {@code .so} names. Matching is derived from <em>this scan's</em>
 * {@code applicationId} / bundle identifier — there is no per-app brand list.
 *
 * <h2>Android first-party prefix rule</h2>
 * From any {@code applicationId} such as {@code com.example.foo.staging}:
 * <ul>
 *   <li>exact id {@code com.example.foo.staging} and children
 *       {@code com.example.foo.staging.*}</li>
 *   <li>parent after dropping the last segment when the id has ≥ 3 segments:
 *       {@code com.example.foo.} — includes siblings such as
 *       {@code com.example.foo.sdk}</li>
 * </ul>
 * Matching uses {@code equals} or {@code startsWith(prefix + ".")} so
 * {@code com.example.foox} is <em>not</em> treated as first-party.
 * Never drop below two segments (won't treat {@code com.} as first-party).
 *
 * <p>Native {@code .so} names use the last meaningful id segments (length ≥ 4,
 * skipping generic labels like {@code com}/{@code android}/{@code staging})
 * plus a weak heuristic for {@code libnative-lib.so}. Vendor denylist and the
 * Offensive security-SDK allowlist are generic SDK names (ObjectBox, Bugsnag,
 * Talsec, …), not app brands.
 */
public final class ScanScopeFilter {

    private static final ScanScopeFilter ALL = new ScanScopeFilter(
            ScanScope.ALL, false, "", PackagePlatform.ANDROID, List.of());

    /** Java package prefix: identifiers separated by dots, no path/shell metacharacters. */
    private static final Pattern PACKAGE_PREFIX = Pattern.compile(
            "[A-Za-z_][A-Za-z0-9_]*(\\.[A-Za-z_][A-Za-z0-9_]*){0,20}");

    private static final Set<String> GENERIC_ID_SEGMENTS = Set.of(
            "com", "org", "net", "io", "app", "apps", "application", "android",
            "mobile", "client", "sdk", "staging", "prod", "production", "debug",
            "test", "testing", "beta", "alpha", "internal", "release", "qa", "dev",
            "uat", "demo", "free", "lite", "plus", "pro", "www");

    /**
     * Narrow Offensive-only Java/Kotlin package prefixes (root/RASP/pinning).
     * Keep this list small — not a general third-party allowlist.
     */
    private static final List<String> SECURITY_SDK_PACKAGES = List.of(
            "com.scottyab.rootbeer",
            "com.scottyab",
            "com.kimchangyoun",
            "com.talsec",
            "com.aheaditec",
            "com.promon",
            "com.appguard",
            "com.nprotect",
            "com.appdome",
            "com.datatheorem",
            "com.guardsquare",
            "org.conscrypt",
            "okhttp3.CertificatePinner"
    );

    /** Best-effort CocoaPods / common iOS third-party class prefixes. */
    private static final List<String> IOS_THIRD_PARTY_PREFIXES = List.of(
            "AFHTTP", "AFNetworking", "Alamofire", "SDWebImage", "Kingfisher",
            "SnapKit", "RxSwift", "RxCocoa", "Firebase", "FIRAnalytics",
            "GTMSession", "nanopb", "FBLPromise", "FBSDK", "RealmSwift",
            "ObjectBox", "Bugsnag", "Sentry", "CocoaLumberjack", "Lottie",
            "Starscream", "SwiftyJSON", "ZIPFoundation", "SSZipArchive",
            "SAMKeychain", "TrustKit", "AppsFlyer", "Adjust", "Amplitude",
            "Mixpanel", "OneSignal", "Protobuf"
    );

    private final ScanScope scope;
    private final boolean includeSecuritySdks;
    private final String applicationOrBundleId;
    private final PackagePlatform platform;
    private final List<String> extraPrefixes;
    private final List<String> firstPartyPrefixes;
    private final List<String> brandTokens;

    private ScanScopeFilter(ScanScope scope, boolean includeSecuritySdks,
                            String applicationOrBundleId, PackagePlatform platform,
                            List<String> extraPrefixes) {
        this.scope = scope == null ? ScanScope.FIRST_PARTY : scope;
        this.includeSecuritySdks = includeSecuritySdks;
        this.applicationOrBundleId = applicationOrBundleId == null ? "" : applicationOrBundleId.trim();
        this.platform = platform == null ? PackagePlatform.ANDROID : platform;
        this.extraPrefixes = extraPrefixes == null ? List.of() : List.copyOf(extraPrefixes);
        this.firstPartyPrefixes = firstPartyPrefixes(this.applicationOrBundleId);
        this.brandTokens = brandTokens(this.applicationOrBundleId);
    }

    public static ScanScopeFilter all() {
        return ALL;
    }

    public static ScanScopeFilter from(LlmMode mode, String applicationOrBundleId,
                                       PackagePlatform platform, List<String> extraPrefixes) {
        LlmMode m = mode == null ? LlmMode.SUMMARIZE : mode;
        return new ScanScopeFilter(
                m.scanScope(),
                m.includeSecuritySdks(),
                applicationOrBundleId,
                platform,
                extraPrefixes);
    }

    public static ScanScopeFilter from(AnalyzeOptions opts, String applicationOrBundleId,
                                       PackagePlatform platform) {
        LlmMode mode = opts == null || opts.llmMode() == null ? LlmMode.SUMMARIZE : opts.llmMode();
        List<String> extra = opts == null ? List.of() : opts.extraPackagePrefixes();
        return from(mode, applicationOrBundleId, platform, extra);
    }

    public ScanScope scope() {
        return scope;
    }

    public boolean includeSecuritySdks() {
        return includeSecuritySdks;
    }

    public boolean isAll() {
        return scope == ScanScope.ALL;
    }

    /**
     * Validate a user-supplied {@code --include-package} value.
     * Returns a normalized prefix, or {@code null} if rejected.
     * Used only as a class-name prefix — never as a filesystem path.
     */
    public static String sanitizePackagePrefix(String raw) {
        if (raw == null) return null;
        String s = raw.trim();
        if (s.endsWith(".")) s = s.substring(0, s.length() - 1);
        if (s.isEmpty() || s.length() > 200) return null;
        if (s.indexOf('/') >= 0 || s.indexOf('\\') >= 0 || s.contains("..") || s.indexOf('\0') >= 0)
            return null;
        if (!PACKAGE_PREFIX.matcher(s).matches()) return null;
        return s;
    }

    /**
     * Prefixes derived from an Android applicationId / iOS bundle id.
     * See class javadoc for the drop-last-segment rule.
     */
    public static List<String> firstPartyPrefixes(String applicationId) {
        if (applicationId == null || applicationId.isBlank()) return List.of();
        String id = applicationId.trim();
        LinkedHashSet<String> out = new LinkedHashSet<>();
        out.add(id);
        String[] parts = id.split("\\.");
        if (parts.length >= 3) {
            StringBuilder parent = new StringBuilder(parts[0]);
            for (int i = 1; i < parts.length - 1; i++)
                parent.append('.').append(parts[i]);
            out.add(parent.toString());
        }
        return List.copyOf(out);
    }

    /**
     * Last meaningful segments of an applicationId / bundle id for native {@code .so}
     * name matching. Not a hardcoded brand list — tokens come only from {@code applicationId}.
     */
    static List<String> brandTokens(String applicationId) {
        if (applicationId == null || applicationId.isBlank()) return List.of();
        List<String> tokens = new ArrayList<>();
        for (String part : applicationId.split("\\.")) {
            String p = part.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]", "");
            if (p.length() >= 4 && !GENERIC_ID_SEGMENTS.contains(p))
                tokens.add(p);
        }
        if (tokens.size() > 2)
            tokens = tokens.subList(tokens.size() - 2, tokens.size());
        return List.copyOf(tokens);
    }

    public boolean includeFunction(SqliteStore.DecompilationResult fn) {
        if (fn == null) return false;
        return includeClass(fn.className());
    }

    public boolean includeClass(String className) {
        if (isAll()) return true;
        if (className == null || className.isBlank()) return true;
        String n = className.replace('/', '.').replace('\\', '.');

        if (n.startsWith("native:"))
            return includeNativeLib(nativeLibName(n));

        if (platform == PackagePlatform.ANDROID)
            return includeAndroidClass(n);
        return includeIosClass(n);
    }

    public boolean includeNativeLib(String soFileName) {
        if (soFileName == null || soFileName.isBlank()) return isAll();
        if (isAll()) return true;
        if (AndroidNativeLibraryDefinitions.isNdkSystemLib(soFileName))
            return false;
        if (includeSecuritySdks && AndroidNativeLibraryDefinitions.isSecuritySdkLib(soFileName))
            return true;
        if (AndroidNativeLibraryDefinitions.isVendorLib(soFileName))
            return false;
        String stem = AndroidNativeLibraryDefinitions.stem(soFileName);
        for (String token : brandTokens) {
            if (stem.contains(token)) return true;
        }
        return AndroidNativeLibraryDefinitions.isGenericAppJni(soFileName);
    }

    private boolean includeAndroidClass(String fqcn) {
        if (matchesAnyPrefix(fqcn, firstPartyPrefixes) || matchesAnyPrefix(fqcn, extraPrefixes))
            return true;
        if (AndroidLibraryDefinitions.shouldSkip(fqcn)) return false;
        return includeSecuritySdks && matchesAnyPrefix(fqcn, SECURITY_SDK_PACKAGES);
    }

    /**
     * iOS Fast/Offensive: skip Apple frameworks and known pods. Remaining classes
     * stay in-scope (ObjC names rarely match a bundle-id prefix). Full Scan = all.
     * No per-app class-name allowlist.
     */
    private boolean includeIosClass(String className) {
        String simple = className.contains(".")
                ? className.substring(className.lastIndexOf('.') + 1)
                : className;
        for (String lib : LibraryDefinitions.getDefaultLibraries()) {
            if (simple.equals(lib) || className.contains(lib))
                return false;
        }
        for (String p : IOS_THIRD_PARTY_PREFIXES) {
            if (simple.startsWith(p) || className.contains(p)) {
                return includeSecuritySdks && isIosSecurityName(simple);
            }
        }
        return true;
    }

    private static boolean isIosSecurityName(String simple) {
        String l = simple.toLowerCase(Locale.ROOT);
        return l.contains("trustkit") || l.contains("jailbreak") || l.contains("frida")
                || l.contains("talsec") || l.contains("promon") || l.contains("appguard");
    }

    static boolean matchesAnyPrefix(String fqcn, List<String> prefixes) {
        if (fqcn == null || prefixes == null || prefixes.isEmpty()) return false;
        String lower = fqcn.toLowerCase(Locale.ROOT);
        for (String raw : prefixes) {
            if (raw == null || raw.isBlank()) continue;
            String p = raw.endsWith(".") ? raw.substring(0, raw.length() - 1) : raw;
            String pl = p.toLowerCase(Locale.ROOT);
            if (lower.equals(pl) || lower.startsWith(pl + "."))
                return true;
        }
        return false;
    }

    /** {@code native:libfoo.so} or {@code native:libfoo.so/Class}. */
    static String nativeLibName(String className) {
        String rest = className.substring("native:".length());
        int slash = rest.indexOf('/');
        return slash >= 0 ? rest.substring(0, slash) : rest;
    }
}
