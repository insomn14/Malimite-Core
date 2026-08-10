package io.malimite.core;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Static security-controls inventory. Answers "what protections appear implemented?"
 * separately from {@link VulnerabilityScanner} weakness findings.
 */
public final class AssessmentScanner {

    private static final Logger log = LoggerFactory.getLogger(AssessmentScanner.class);

    private static final Pattern SHORT_CLASS = Pattern.compile(
            "^[a-z](\\.[a-z\\d]){0,6}$|^[a-z]{1,2}\\.[a-z]{1,2}(\\.[a-z\\d]{1,3})+$");

    private static final Map<String, String> VENDOR_MARKERS = Map.ofEntries(
            Map.entry("dexguard", "DexGuard"),
            Map.entry("ixguard", "iXGuard"),
            Map.entry("dexprotector", "DexProtector"),
            Map.entry("guardsquare", "Guardsquare"),
            Map.entry("promon", "Promon"),
            Map.entry("appdome", "Appdome"),
            Map.entry("talsec", "Talsec"),
            Map.entry("freerasp", "FreeRASP"),
            Map.entry("arxan", "Arxan/Digital.ai"),
            Map.entry("bangcle", "Bangcle"),
            Map.entry("jiagu", "Qihoo Jiagu"),
            Map.entry("libjiagu", "Qihoo Jiagu"),
            Map.entry("secneo", "SecNeo"),
            Map.entry("ijiami", "Ijiami"),
            Map.entry("kiwisec", "KiwiSec"),
            Map.entry("approov", "Approov"),
            Map.entry("verimatrix", "Verimatrix")
    );

    public int scan(SqliteStore store, String executableName, PackagePlatform platform) {
        long t0 = System.currentTimeMillis();
        store.clearAssessments(executableName);

        ScanCtx ctx = ScanCtx.load(store, executableName, platform);
        List<AssessmentResult> results = new ArrayList<>();
        if (platform == PackagePlatform.ANDROID) {
            assessAndroid(ctx, results);
        } else {
            assessIos(ctx, results);
        }

        for (AssessmentResult r : results)
            store.insertAssessment(r, executableName);

        log.info("AssessmentScanner: {} control(s) for {} in {}ms",
                results.size(), platform, System.currentTimeMillis() - t0);
        return results.size();
    }

    // ── Android ───────────────────────────────────────────────────────────────

    private void assessAndroid(ScanCtx ctx, List<AssessmentResult> out) {
        out.add(assessJavaObfuscation(ctx));
        out.add(assessObfuscatorVendor(ctx));
        out.add(assessNativeObfuscation(ctx));
        out.add(assessPacker(ctx));

        out.add(presence(ctx, "ASSESS-ROOT-DETECTION", "Root detection", "DETECTION",
                "HIGH", List.of(
                        Pattern.compile("(?i)rootbeer|magisk|/system/(?:bin|xbin)/su|Superuser\\.apk|test-keys"),
                        Pattern.compile("(?i)isRooted|checkRoot|RootCloak")
                ), Map.of("signal", "root_jailbreak")));

        out.add(presence(ctx, "ASSESS-FRIDA-DETECTION", "Frida / instrumentation detection", "DETECTION",
                "HIGH", List.of(
                        Pattern.compile("(?i)frida|gum-js-loop|LIBFRIDA|frida-server|27042"),
                        Pattern.compile("(?i)xposed|substrate|cynject|frida::")
                ), Map.of("signal", "instrumentation")));

        out.add(presence(ctx, "ASSESS-DEBUG-DETECTION", "Debugger detection", "DETECTION",
                "MEDIUM", List.of(
                        Pattern.compile("isDebuggerConnected"),
                        Pattern.compile("(?i)TracerPid|Debug\\.isDebuggerConnected|FLAG_DEBUGGABLE")
                ), Map.of()));

        out.add(presence(ctx, "ASSESS-EMULATOR-DETECTION", "Emulator detection", "DETECTION",
                "MEDIUM", List.of(
                        Pattern.compile("(?i)goldfish|ranchu|generic_x86| Emulator|isEmulator|qemu")
                ), Map.of()));

        out.add(presence(ctx, "ASSESS-INTEGRITY", "Integrity / Play Integrity / SafetyNet", "DETECTION",
                "HIGH", List.of(
                        Pattern.compile("(?i)PlayIntegrity|SafetyNet|IntegrityManager|Nonce\\.Builder"),
                        Pattern.compile("(?i)PackageManager\\.GET_SIGNATURES|signingInfo|hasSignature")
                ), Map.of()));

        out.add(assessSslPinningAndroid(ctx));
        out.add(assessCleartextBlocked(ctx));

        out.add(presence(ctx, "ASSESS-FLAG-SECURE", "FLAG_SECURE (screen capture protection)", "UI_PRIVACY",
                "HIGH", List.of(
                        Pattern.compile("FLAG_SECURE"),
                        Pattern.compile("(?i)setFlags\\s*\\([^)]*FLAG_SECURE|addFlags\\s*\\([^)]*FLAG_SECURE")
                ), Map.of()));

        out.add(presence(ctx, "ASSESS-TOUCH-FILTER", "Touch filter / overlay hardening", "UI_PRIVACY",
                "MEDIUM", List.of(
                        Pattern.compile("filterTouchesWhenObscured"),
                        Pattern.compile("setOnFilterTouchEventListener|FILTER_TOUCHES")
                ), Map.of()));

        out.add(assessBackupAndroid(ctx));
        out.add(assessDebuggableDisabled(ctx));
        out.add(assessNativeHardening(ctx));
        out.add(assessKeystore(ctx));
        out.add(assessBiometricAndroid(ctx));
        out.add(assessAccessibilityDefense(ctx));
        out.add(assessSecuritySdkInventory(ctx));
    }

    // ── iOS ───────────────────────────────────────────────────────────────────

    private void assessIos(ScanCtx ctx, List<AssessmentResult> out) {
        out.add(assessIosObfuscation(ctx));
        out.add(assessObfuscatorVendor(ctx));

        out.add(presence(ctx, "ASSESS-JAILBREAK-DETECTION", "Jailbreak detection", "DETECTION",
                "HIGH", List.of(
                        Pattern.compile("(?i)cydia|substrate|/var/jb|/Applications/Cydia|/usr/sbin/sshd|apt-get")
                ), Map.of("signal", "root_jailbreak")));

        out.add(presence(ctx, "ASSESS-FRIDA-DETECTION", "Frida / instrumentation detection", "DETECTION",
                "HIGH", List.of(
                        Pattern.compile("(?i)frida|cynject|cycript|libsubstrate|FridaGadget")
                ), Map.of("signal", "instrumentation")));

        out.add(presence(ctx, "ASSESS-ANTIDEBUG", "Anti-debug (ptrace / deny attach)", "DETECTION",
                "HIGH", List.of(
                        Pattern.compile("(?i)PT_DENY_ATTACH|ptrace|P_TRACED|KERN_PROC|sysctl")
                ), Map.of()));

        out.add(presence(ctx, "ASSESS-INTEGRITY", "DeviceCheck / App Attest / integrity", "DETECTION",
                "MEDIUM", List.of(
                        Pattern.compile("(?i)DeviceCheck|DCAppAttest|AppAttest|SecCodeCheckValidity")
                ), Map.of()));

        out.add(assessSslPinningIos(ctx));
        out.add(assessAts(ctx));

        out.add(presence(ctx, "ASSESS-SCREEN-CAPTURE", "Screen capture / secure text protections", "UI_PRIVACY",
                "LOW", List.of(
                        Pattern.compile("(?i)isSecureTextEntry|UITextFieldSecure|screen.?capture|UIScreenCapturedDidChange")
                ), Map.of()));

        out.add(assessGetTaskAllow(ctx));
        out.add(assessPie(ctx));
        out.add(assessKeychain(ctx));
        out.add(assessBiometricIos(ctx));
        out.add(assessSecuritySdkInventory(ctx));
    }

    // ── shared detectors ──────────────────────────────────────────────────────

    private AssessmentResult assessJavaObfuscation(ScanCtx ctx) {
        Map<String, List<String>> classes = ctx.classes;
        int app = 0, shortNames = 0;
        for (String cn : classes.keySet()) {
            if (cn == null || cn.startsWith("native:")) continue;
            if (AndroidLibraryDefinitions.shouldSkip(cn)) continue;
            app++;
            String simple = cn.contains(".") ? cn.substring(cn.lastIndexOf('.') + 1) : cn;
            if (simple.length() <= 2 || SHORT_CLASS.matcher(cn).matches())
                shortNames++;
        }
        if (app == 0) {
            return result(ctx, "ASSESS-OBFUSCATION-JAVA", "Java/Kotlin obfuscation", "OBFUSCATION",
                    AssessmentStatus.UNKNOWN, "LOW", List.of("No app classes to evaluate"), Map.of());
        }
        double ratio = (double) shortNames / app;
        AssessmentStatus st;
        String tech = "NONE";
        if (ratio >= 0.55) { st = AssessmentStatus.PRESENT; tech = "R8_OR_PROGUARD"; }
        else if (ratio >= 0.15) { st = AssessmentStatus.PARTIAL; tech = "R8_OR_PROGUARD_PARTIAL"; }
        else { st = AssessmentStatus.ABSENT; }
        return result(ctx, "ASSESS-OBFUSCATION-JAVA", "Java/Kotlin obfuscation", "OBFUSCATION",
                st, "MEDIUM",
                List.of(shortNames + "/" + app + " app classes look obfuscated (ratio="
                        + String.format(Locale.ROOT, "%.2f", ratio) + ")"),
                Map.of("technique", tech, "obfuscatedRatio", String.format(Locale.ROOT, "%.2f", ratio)));
    }

    private AssessmentResult assessIosObfuscation(ScanCtx ctx) {
        // Heuristic: many Swift/ObjC symbols with short or mangled-only names
        int total = 0, obscure = 0;
        for (String cn : ctx.classes.keySet()) {
            if (cn == null || "Libraries".equals(cn) || "Global".equals(cn)) continue;
            total++;
            if (cn.length() <= 3 || cn.startsWith("_$s") || cn.matches("[A-Z]{1,2}"))
                obscure++;
        }
        if (total == 0) {
            return result(ctx, "ASSESS-OBFUSCATION-IOS", "Symbol / name obfuscation", "OBFUSCATION",
                    AssessmentStatus.UNKNOWN, "LOW", List.of("Insufficient class metadata"), Map.of());
        }
        double ratio = (double) obscure / total;
        AssessmentStatus st = ratio >= 0.4 ? AssessmentStatus.PRESENT
                : ratio >= 0.1 ? AssessmentStatus.PARTIAL : AssessmentStatus.ABSENT;
        return result(ctx, "ASSESS-OBFUSCATION-IOS", "Symbol / name obfuscation", "OBFUSCATION",
                st, "LOW",
                List.of(obscure + "/" + total + " class names look obscured"),
                Map.of("obfuscatedRatio", String.format(Locale.ROOT, "%.2f", ratio)));
    }

    private AssessmentResult assessObfuscatorVendor(ScanCtx ctx) {
        List<String> hits = new ArrayList<>();
        String vendor = null;
        String blob = ctx.allTextLower;
        for (var e : VENDOR_MARKERS.entrySet()) {
            if (blob.contains(e.getKey())) {
                hits.add(e.getValue() + " marker (" + e.getKey() + ")");
                if (vendor == null) vendor = e.getValue();
            }
        }
        if (vendor != null) {
            return result(ctx, "ASSESS-OBFUSCATOR-VENDOR", "Third-party obfuscator / app shield", "OBFUSCATION",
                    AssessmentStatus.PRESENT, "HIGH", hits, Map.of("vendor", vendor));
        }
        return result(ctx, "ASSESS-OBFUSCATOR-VENDOR", "Third-party obfuscator / app shield", "OBFUSCATION",
                AssessmentStatus.ABSENT, "MEDIUM",
                List.of("No known commercial shield/obfuscator fingerprints"), Map.of());
    }

    private AssessmentResult assessNativeObfuscation(ScanCtx ctx) {
        boolean hasNative = ctx.classes.keySet().stream().anyMatch(c -> c != null && c.startsWith("native:"));
        if (!hasNative && !ctx.resourceTextLower.contains("native-lib")
                && !ctx.resourceTextLower.contains("nativelib")) {
            return result(ctx, "ASSESS-OBFUSCATION-NATIVE", "Native library obfuscation", "OBFUSCATION",
                    AssessmentStatus.UNKNOWN, "LOW", List.of("No native libs observed"), Map.of());
        }
        boolean mangled = ctx.anyMatch(
                Pattern.compile("(?i)ollvm|fla_|bcf_|sub_"),
                Pattern.compile("Java_[a-z]_[a-z]_"));
        if (mangled) {
            return result(ctx, "ASSESS-OBFUSCATION-NATIVE", "Native library obfuscation", "OBFUSCATION",
                    AssessmentStatus.PARTIAL, "LOW",
                    List.of("Possible native obfuscation / mangled JNI symbols"), Map.of());
        }
        return result(ctx, "ASSESS-OBFUSCATION-NATIVE", "Native library obfuscation", "OBFUSCATION",
                AssessmentStatus.UNKNOWN, "LOW",
                List.of("Native libs present; obfuscation not confirmed statically"), Map.of());
    }

    private AssessmentResult assessPacker(ScanCtx ctx) {
        Pattern p = Pattern.compile("(?i)libjiagu|libsecexe|libsecmain|load_dex|shell\\.dex|secshell");
        if (ctx.anyMatch(p)) {
            return result(ctx, "ASSESS-PACKER", "Packer / encrypted DEX shell", "OBFUSCATION",
                    AssessmentStatus.PRESENT, "MEDIUM",
                    List.of("Packer/shell loader indicators found"), Map.of());
        }
        return result(ctx, "ASSESS-PACKER", "Packer / encrypted DEX shell", "OBFUSCATION",
                AssessmentStatus.ABSENT, "MEDIUM", List.of("No common packer markers"), Map.of());
    }

    private AssessmentResult assessSslPinningAndroid(ScanCtx ctx) {
        List<String> styles = new ArrayList<>();
        List<String> evidence = new ArrayList<>();
        if (ctx.anyMatch(Pattern.compile("CertificatePinner"))) {
            styles.add("DYNAMIC_OKHTTP");
            evidence.add("OkHttp CertificatePinner");
        }
        if (ctx.resourceText.contains("NSC=pin-set-present")
                || ctx.anyMatch(Pattern.compile("(?i)pin-set|pin digest|NetworkSecurityConfig.*pin"))) {
            styles.add("STATIC_NSC");
            evidence.add("Network Security Config pin-set");
        }
        if (ctx.anyMatch(Pattern.compile("(?i)TrustKit|SSLPinner|PublicKeyPinning|sha256/"))) {
            styles.add("CUSTOM_OR_TRUSTKIT");
            evidence.add("TrustKit / public-key pin patterns");
        }
        if (ctx.anyMatch(Pattern.compile("X509TrustManager"))
                && ctx.anyMatch(Pattern.compile("(?i)pin|spki|checkServerTrusted"))) {
            styles.add("CUSTOM_TRUSTMANAGER");
            evidence.add("Custom TrustManager with pin-like checks");
        }
        if (styles.isEmpty()) {
            return result(ctx, "ASSESS-SSL-PINNING", "SSL / certificate pinning", "NETWORK",
                    AssessmentStatus.ABSENT, "MEDIUM",
                    List.of("No OkHttp CertificatePinner, NSC pin-set, or TrustKit-like signals"),
                    Map.of("style", "ABSENT"));
        }
        return result(ctx, "ASSESS-SSL-PINNING", "SSL / certificate pinning", "NETWORK",
                AssessmentStatus.PRESENT, "HIGH", evidence, Map.of("style", String.join(",", styles)));
    }

    private AssessmentResult assessSslPinningIos(ScanCtx ctx) {
        List<String> styles = new ArrayList<>();
        List<String> evidence = new ArrayList<>();
        if (ctx.anyMatch(Pattern.compile("(?i)TrustKit|TSKPinningValidator|NSPinnedDomains"))) {
            styles.add("STATIC_TRUSTKIT");
            evidence.add("TrustKit / NSPinnedDomains");
        }
        if (ctx.anyMatch(Pattern.compile("(?i)SecTrustEvaluate|pinnedPublicKey|SSLPinning"))) {
            styles.add("CUSTOM");
            evidence.add("Custom trust evaluation / SSLPinning symbols");
        }
        if (styles.isEmpty()) {
            return result(ctx, "ASSESS-SSL-PINNING", "SSL / certificate pinning", "NETWORK",
                    AssessmentStatus.ABSENT, "MEDIUM",
                    List.of("No TrustKit / NSPinnedDomains / pin symbols"), Map.of("style", "ABSENT"));
        }
        return result(ctx, "ASSESS-SSL-PINNING", "SSL / certificate pinning", "NETWORK",
                AssessmentStatus.PRESENT, "HIGH", evidence, Map.of("style", String.join(",", styles)));
    }

    private AssessmentResult assessCleartextBlocked(ScanCtx ctx) {
        boolean blocked = ctx.resourceText.contains("UsesCleartextTraffic=false")
                || ctx.anyMatch(Pattern.compile("usesCleartextTraffic\\s*=\\s*false"));
        boolean allowed = ctx.resourceText.contains("UsesCleartextTraffic=true")
                || ctx.anyMatch(Pattern.compile("usesCleartextTraffic\\s*=\\s*true"));
        if (blocked && !allowed) {
            return result(ctx, "ASSESS-CLEARTEXT-BLOCKED", "Cleartext traffic blocked", "NETWORK",
                    AssessmentStatus.PRESENT, "HIGH",
                    List.of("usesCleartextTraffic=false"), Map.of());
        }
        if (allowed) {
            return result(ctx, "ASSESS-CLEARTEXT-BLOCKED", "Cleartext traffic blocked", "NETWORK",
                    AssessmentStatus.ABSENT, "HIGH",
                    List.of("usesCleartextTraffic=true"), Map.of());
        }
        return result(ctx, "ASSESS-CLEARTEXT-BLOCKED", "Cleartext traffic blocked", "NETWORK",
                AssessmentStatus.UNKNOWN, "LOW",
                List.of("Cleartext flag not found in resources"), Map.of());
    }

    private AssessmentResult assessAts(ScanCtx ctx) {
        if (ctx.anyMatch(Pattern.compile("(?i)NSAllowsArbitraryLoads\\s*[=:]\\s*true|NSAppTransportSecurity"))) {
            boolean allows = ctx.anyMatch(Pattern.compile("(?i)NSAllowsArbitraryLoads\\s*[=:]\\s*(YES|true|1)"));
            return result(ctx, "ASSESS-ATS", "App Transport Security posture", "NETWORK",
                    allows ? AssessmentStatus.ABSENT : AssessmentStatus.PRESENT, "MEDIUM",
                    List.of(allows ? "NSAllowsArbitraryLoads enabled" : "ATS configuration present"),
                    Map.of());
        }
        return result(ctx, "ASSESS-ATS", "App Transport Security posture", "NETWORK",
                AssessmentStatus.PRESENT, "LOW",
                List.of("No ATS bypass markers (default ATS assumed)"), Map.of());
    }

    private AssessmentResult assessBackupAndroid(ScanCtx ctx) {
        if (ctx.resourceText.contains("AllowBackup=false")
                || ctx.anyMatch(Pattern.compile("(?i)allowBackup\\s*=\\s*false"))) {
            return result(ctx, "ASSESS-BACKUP-DISABLED", "Backup disabled (allowBackup=false)", "UI_PRIVACY",
                    AssessmentStatus.PRESENT, "HIGH", List.of("allowBackup=false"), Map.of());
        }
        if (ctx.resourceText.contains("AllowBackup=true")
                || ctx.anyMatch(Pattern.compile("(?i)allowBackup\\s*=\\s*true"))) {
            return result(ctx, "ASSESS-BACKUP-DISABLED", "Backup disabled (allowBackup=false)", "UI_PRIVACY",
                    AssessmentStatus.ABSENT, "HIGH", List.of("allowBackup=true"), Map.of());
        }
        return result(ctx, "ASSESS-BACKUP-DISABLED", "Backup disabled (allowBackup=false)", "UI_PRIVACY",
                AssessmentStatus.UNKNOWN, "LOW", List.of("allowBackup not found"), Map.of());
    }

    private AssessmentResult assessDebuggableDisabled(ScanCtx ctx) {
        if (ctx.resourceText.contains("Debuggable=true")
                || ctx.anyMatch(Pattern.compile("(?i)android:debuggable\\s*=\\s*\"?true"))) {
            return result(ctx, "ASSESS-DEBUGGABLE-OFF", "Release build not debuggable", "DETECTION",
                    AssessmentStatus.ABSENT, "HIGH", List.of("android:debuggable=true"), Map.of());
        }
        if (ctx.resourceText.contains("Debuggable=false")) {
            return result(ctx, "ASSESS-DEBUGGABLE-OFF", "Release build not debuggable", "DETECTION",
                    AssessmentStatus.PRESENT, "HIGH", List.of("android:debuggable=false"), Map.of());
        }
        return result(ctx, "ASSESS-DEBUGGABLE-OFF", "Release build not debuggable", "DETECTION",
                AssessmentStatus.PRESENT, "LOW",
                List.of("debuggable not explicitly true (release default assumed)"), Map.of());
    }

    private AssessmentResult assessGetTaskAllow(ScanCtx ctx) {
        if (ctx.anyMatch(Pattern.compile("(?i)get-task-allow"))) {
            return result(ctx, "ASSESS-GET-TASK-ALLOW-OFF", "get-task-allow disabled (no debug entitlement)", "DETECTION",
                    AssessmentStatus.ABSENT, "HIGH", List.of("get-task-allow entitlement present"), Map.of());
        }
        return result(ctx, "ASSESS-GET-TASK-ALLOW-OFF", "get-task-allow disabled (no debug entitlement)", "DETECTION",
                AssessmentStatus.PRESENT, "MEDIUM", List.of("get-task-allow not found"), Map.of());
    }

    private AssessmentResult assessNativeHardening(ScanCtx ctx) {
        boolean hasPic = ctx.resourceText.contains("NativeLibPic=");
        boolean picDisabled = ctx.resourceText.contains("NativeLibPic=")
                && ctx.resourceText.contains("=disabled");
        // Narrow: only count PIC disabled rows
        picDisabled = Pattern.compile("NativeLibPic=.+=disabled").matcher(ctx.resourceText).find();
        boolean canaryDisabled = Pattern.compile("NativeLibStackCanary=.+=disabled")
                .matcher(ctx.resourceText).find();
        boolean canaryEnabled = Pattern.compile("NativeLibStackCanary=.+=enabled")
                .matcher(ctx.resourceText).find();
        boolean debugPresent = Pattern.compile("NativeLibDebugSymbols=.+=present")
                .matcher(ctx.resourceText).find();

        if (!hasPic) {
            return result(ctx, "ASSESS-NATIVE-HARDENING", "Native ELF hardening (PIC/canary/strip)", "NATIVE",
                    AssessmentStatus.UNKNOWN, "LOW",
                    List.of("No ELF protection resources (no arm64 libs analyzed)"), Map.of());
        }
        List<String> ev = new ArrayList<>();
        if (picDisabled) ev.add("PIC disabled on at least one .so");
        else ev.add("PIC/DYN enabled");
        if (canaryDisabled) ev.add("Stack canary missing on at least one .so");
        else if (canaryEnabled) ev.add("Stack canary present");
        if (debugPresent) ev.add("Debug symbols present on at least one .so");
        else ev.add("Symbols appear stripped");

        AssessmentStatus st;
        if (picDisabled || canaryDisabled) st = AssessmentStatus.PARTIAL;
        else if (debugPresent) st = AssessmentStatus.PARTIAL;
        else st = AssessmentStatus.PRESENT;
        return result(ctx, "ASSESS-NATIVE-HARDENING", "Native ELF hardening (PIC/canary/strip)", "NATIVE",
                st, "HIGH", ev, Map.of());
    }

    private AssessmentResult assessPie(ScanCtx ctx) {
        if (ctx.resourceText.contains("MH_PIE=1")) {
            return result(ctx, "ASSESS-PIE", "PIE (position independent executable)", "NATIVE",
                    AssessmentStatus.PRESENT, "HIGH", List.of("MH_PIE=1"), Map.of());
        }
        if (ctx.resourceText.contains("MH_PIE=0")) {
            return result(ctx, "ASSESS-PIE", "PIE (position independent executable)", "NATIVE",
                    AssessmentStatus.ABSENT, "HIGH", List.of("MH_PIE=0"), Map.of());
        }
        return result(ctx, "ASSESS-PIE", "PIE (position independent executable)", "NATIVE",
                AssessmentStatus.UNKNOWN, "LOW", List.of("Mach-O PIE flag not recorded"), Map.of());
    }

    private AssessmentResult assessKeystore(ScanCtx ctx) {
        return presence(ctx, "ASSESS-KEYSTORE", "Android Keystore usage", "CRYPTO",
                "MEDIUM", List.of(
                        Pattern.compile("AndroidKeyStore|KeyGenParameterSpec|KeyStore\\.getInstance")
                ), Map.of());
    }

    private AssessmentResult assessKeychain(ScanCtx ctx) {
        return presence(ctx, "ASSESS-KEYCHAIN", "Keychain Services usage", "CRYPTO",
                "MEDIUM", List.of(
                        Pattern.compile("(?i)SecItemAdd|kSecClassGenericPassword|kSecAttrAccessible")
                ), Map.of());
    }

    private AssessmentResult assessBiometricAndroid(ScanCtx ctx) {
        return presence(ctx, "ASSESS-BIOMETRIC", "BiometricPrompt / fingerprint auth", "AUTH",
                "MEDIUM", List.of(
                        Pattern.compile("BiometricPrompt|FingerprintManager|BiometricManager")
                ), Map.of());
    }

    private AssessmentResult assessBiometricIos(ScanCtx ctx) {
        return presence(ctx, "ASSESS-BIOMETRIC", "LocalAuthentication / biometrics", "AUTH",
                "MEDIUM", List.of(
                        Pattern.compile("(?i)LocalAuthentication|LAContext|evaluatePolicy|biometryType")
                ), Map.of());
    }

    private AssessmentResult assessAccessibilityDefense(ScanCtx ctx) {
        boolean a11y = ctx.anyMatch(Pattern.compile(
                "(?i)AccessibilityService|BIND_ACCESSIBILITY_SERVICE|canRequestTouchExplorationMode"));
        boolean defend = ctx.anyMatch(Pattern.compile(
                "(?i)filterTouchesWhenObscured|FLAG_SECURE|anti.?overlay|autoclick"));
        if (defend) {
            return result(ctx, "ASSESS-A11Y-DEFENSE", "Accessibility / autoclicker abuse defenses", "DETECTION",
                    AssessmentStatus.PARTIAL, "LOW",
                    List.of("UI hardening signals that may mitigate a11y abuse"), Map.of());
        }
        if (a11y) {
            return result(ctx, "ASSESS-A11Y-DEFENSE", "Accessibility / autoclicker abuse defenses", "DETECTION",
                    AssessmentStatus.UNKNOWN, "LOW",
                    List.of("Accessibility APIs referenced; defense posture unclear"), Map.of());
        }
        return result(ctx, "ASSESS-A11Y-DEFENSE", "Accessibility / autoclicker abuse defenses", "DETECTION",
                AssessmentStatus.UNKNOWN, "LOW",
                List.of("No clear accessibility-abuse defense signals"), Map.of());
    }

    private AssessmentResult assessSecuritySdkInventory(ScanCtx ctx) {
        List<String> sdks = new ArrayList<>();
        for (var e : VENDOR_MARKERS.entrySet()) {
            if (ctx.allTextLower.contains(e.getKey()) && !sdks.contains(e.getValue()))
                sdks.add(e.getValue());
        }
        if (ctx.anyMatch(Pattern.compile("(?i)RootBeer"))) sdks.add("RootBeer");
        if (sdks.isEmpty()) {
            return result(ctx, "ASSESS-SECURITY-SDK", "Third-party security SDK inventory", "SDKS",
                    AssessmentStatus.ABSENT, "MEDIUM",
                    List.of("No known security/RASP SDK fingerprints"), Map.of());
        }
        return result(ctx, "ASSESS-SECURITY-SDK", "Third-party security SDK inventory", "SDKS",
                AssessmentStatus.PRESENT, "HIGH",
                List.of("Detected: " + String.join(", ", sdks)),
                Map.of("sdks", String.join(",", sdks)));
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private AssessmentResult presence(ScanCtx ctx, String id, String title, String category,
                                      String confidence, List<Pattern> patterns,
                                      Map<String, String> detail) {
        List<String> hits = new ArrayList<>();
        for (Pattern p : patterns) {
            String h = ctx.firstMatch(p);
            if (h != null) hits.add(truncate(h, 120));
        }
        if (!hits.isEmpty()) {
            return result(ctx, id, title, category, AssessmentStatus.PRESENT, confidence, hits, detail);
        }
        return result(ctx, id, title, category, AssessmentStatus.ABSENT, confidence,
                List.of("No matching signals in strings/decompilation/resources"), detail);
    }

    private static AssessmentResult result(ScanCtx ctx, String id, String title, String category,
                                           AssessmentStatus status, String confidence,
                                           List<String> evidence, Map<String, String> detail) {
        return new AssessmentResult(id, title, category, status, confidence, evidence, detail,
                ctx.platform.name());
    }

    private static String truncate(String s, int max) {
        if (s == null) return "";
        String t = s.replaceAll("\\s+", " ").trim();
        return t.length() <= max ? t : t.substring(0, max) + "…";
    }

    /** Preloaded scan corpus for detectors. */
    static final class ScanCtx {
        final PackagePlatform platform;
        final Map<String, List<String>> classes;
        final String allTextLower;
        final String resourceText;
        final String resourceTextLower;
        final String decompSample;
        final String stringsSample;

        private ScanCtx(PackagePlatform platform, Map<String, List<String>> classes,
                        String allTextLower, String resourceText, String decompSample, String stringsSample) {
            this.platform = platform;
            this.classes = classes;
            this.allTextLower = allTextLower;
            this.resourceText = resourceText;
            this.resourceTextLower = resourceText.toLowerCase(Locale.ROOT);
            this.decompSample = decompSample;
            this.stringsSample = stringsSample;
        }

        static ScanCtx load(SqliteStore store, String executableName, PackagePlatform platform) {
            Map<String, List<String>> classes = store.getClassesAndFunctions(executableName);
            StringBuilder resources = new StringBuilder();
            for (Map<String, String> r : store.getResourceStrings()) {
                resources.append(r.getOrDefault("resourceId", "")).append('=')
                        .append(r.getOrDefault("value", "")).append('\n');
            }
            StringBuilder strings = new StringBuilder();
            for (Map<String, String> s : store.getMachoStrings(executableName, 50_000)) {
                strings.append(s.getOrDefault("value", "")).append('\n');
            }
            StringBuilder decomp = new StringBuilder();
            int n = 0;
            for (var fn : store.getAllDecompiledFunctions(executableName)) {
                if (fn.decompiledCode() == null || fn.decompiledCode().isBlank()) continue;
                // Prefer class index names + a capped decomp sample for regex
                decomp.append(fn.className()).append('.').append(fn.functionName()).append('\n');
                if (n < 400) {
                    String body = fn.decompiledCode();
                    if (body.length() > 2_000) body = body.substring(0, 2_000);
                    decomp.append(body).append('\n');
                    n++;
                }
            }
            String classNames = String.join("\n", classes.keySet());
            String corpus = classNames + "\n" + resources + "\n" + strings + "\n" + decomp;
            return new ScanCtx(platform, classes, corpus.toLowerCase(Locale.ROOT),
                    resources.toString(), decomp.toString(), strings.toString());
        }

        boolean anyMatch(Pattern... patterns) {
            for (Pattern p : patterns) {
                if (p.matcher(decompSample).find()) return true;
                if (p.matcher(stringsSample).find()) return true;
                if (p.matcher(resourceText).find()) return true;
            }
            return false;
        }

        String firstMatch(Pattern p) {
            var m = p.matcher(decompSample);
            if (m.find()) return m.group();
            m = p.matcher(stringsSample);
            if (m.find()) return m.group();
            m = p.matcher(resourceText);
            if (m.find()) return m.group();
            return null;
        }
    }
}
