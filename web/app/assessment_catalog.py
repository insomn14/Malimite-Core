"""How-to metadata for Assessment drawer rows, keyed by control_id + platform.

Mirrors core ``AssessmentCatalog`` so old SQLite scans (no extra columns) still
get summary / static / dynamic steps at API read time.
"""
from __future__ import annotations

from typing import Optional

_ANY = "ANY"

_FALLBACK_STATIC = [
    "Search decompiled code (JADX for Android, Ghidra/Hopper for iOS) for APIs and types related to this control.",
    "Search strings, resources, and the manifest or Info.plist for related flags, permissions, and configuration values.",
    "Cross-check hits against third-party libraries so SDK noise is not mistaken for app-level enforcement.",
]
_FALLBACK_DYNAMIC = [
    "On an authorized test device, exercise the related user flow and record whether the protection is actually enforced at runtime.",
    "Compare behavior on a stock device versus a lab device where the condition this control is meant to detect is present.",
    "Document observed prompts, errors, or degraded functionality. Do not use this as a bypass or exploit recipe.",
]


def _g(summary: str, static_checks: list[str], dynamic_checks: list[str]) -> dict:
    return {
        "summary": summary,
        "static_checks": list(static_checks),
        "dynamic_checks": list(dynamic_checks),
    }


# (control_id, platform) -> guide. Platform ANY matches any OS.
_GUIDES: dict[tuple[str, str], dict] = {
    ("ASSESS-OBFUSCATION-JAVA", "ANDROID"): _g(
        "Estimates whether Java/Kotlin identifiers look renamed (R8/ProGuard-style) based on short or opaque class names.",
        [
            "In JADX, sample app (non-library) class names: many 1–2 character or opaque names suggest R8/ProGuard.",
            "Open gradle/mapping clues in resources if present (mapping.txt is rarely shipped; look for -keep comments or retrace strings).",
            "Compare SDK/library packages (skipped by the scanner) against first-party packages so library names do not hide app obfuscation.",
        ],
        [
            "On an authorized build, compare a debug (unminified) APK against the release APK and note whether class/method names remain readable.",
            "During runtime inspection, check whether stack traces and error reports expose original names or only minified symbols.",
            "Record the observation only — this is an inventory of naming hygiene, not a deobfuscation recipe.",
        ],
    ),
    ("ASSESS-OBFUSCATION-IOS", "IOS"): _g(
        "Estimates whether Objective-C/Swift symbols look stripped or renamed (short, mangled, or opaque class names).",
        [
            "In Ghidra/Hopper/class-dump, review exported class and method names for readable product terms versus short or Swift-mangled-only symbols.",
            "Check whether the binary still contains Objective-C runtime metadata (class dumps) or has been stripped aggressively.",
            "Search strings for leftover selector names that contradict a 'fully obfuscated' appearance.",
        ],
        [
            "On an authorized device, attach a debugger or inspect crash logs and note whether symbol names are meaningful.",
            "Compare a debug/TestFlight build against the App Store binary if both are in scope.",
            "Document naming posture only; do not treat this as a bypass of other protections.",
        ],
    ),
    ("ASSESS-OBFUSCATOR-VENDOR", _ANY): _g(
        "Looks for fingerprints of commercial app-shield / obfuscator vendors (DexGuard, iXGuard, Promon, Talsec, and similar).",
        [
            "Search strings, native library names, and decompilation for vendor markers (dexguard, ixguard, promon, talsec, appdome, arxan, bangcle, jiagu, secneo, etc.).",
            "Inspect packaged .so / framework names for shield loaders or wrapper libraries.",
            "Note which vendor hit, if any — presence of a marker is not proof the shield is correctly configured.",
        ],
        [
            "On an authorized lab device, launch the app and observe whether a shield SDK initializes (network beacons, custom crash handlers, or startup checks).",
            "Record product/version strings shown in logs or about screens when the vendor identifies itself.",
            "Do not attempt to unpack or defeat a commercial shield; inventory only.",
        ],
    ),
    ("ASSESS-OBFUSCATION-NATIVE", "ANDROID"): _g(
        "Checks whether native libraries show obfuscation or mangled JNI symbols (OLLVM-like patterns, opaque JNI names).",
        [
            "List JNI exports in Ghidra/readelf and note whether Java_* names are readable or reduced to short stubs.",
            "Search native strings for OLLVM / control-flow flattening markers (ollvm, fla_, bcf_, sub_).",
            "If no .so files are present, treat native obfuscation as unknown rather than absent.",
        ],
        [
            "On an authorized device, confirm which .so files actually load (System.loadLibrary) during the flows you care about.",
            "Compare symbol richness of those libraries against a known unobfuscated build if available.",
            "Record whether native code appears protected; do not attempt to de-flatten or patch the binary.",
        ],
    ),
    ("ASSESS-PACKER", "ANDROID"): _g(
        "Detects common DEX packer / encrypted-shell loaders (Jiagu, SecNeo-style libsecexe/libsecmain, shell.dex).",
        [
            "Inspect APK native libs and assets for packer names (libjiagu, libsecexe, libsecmain, secshell, shell.dex, load_dex).",
            "In JADX, see whether Application subclasses look like a stub that loads encrypted DEX at runtime.",
            "Check for a very small classes.dex plus large encrypted blobs in assets.",
        ],
        [
            "On an authorized device, watch startup: packers typically decrypt DEX after process start.",
            "Note whether a memory dump after launch shows more classes than the on-disk DEX (inventory, not an unpack how-to).",
            "Do not publish unpacker steps; record packer presence for the assessment only.",
        ],
    ),
    ("ASSESS-ROOT-DETECTION", "ANDROID"): _g(
        "Checks for root / Magisk / Superuser signals (RootBeer, su paths, test-keys, isRooted-style APIs).",
        [
            "In JADX and strings, search for rootbeer, magisk, /system/bin/su, Superuser.apk, test-keys, isRooted, checkRoot, RootCloak.",
            "Identify whether detection lives in app code or a third-party RASP/security SDK.",
            "Review what happens on a positive hit in decompilation (log, dialog, finish(), or a flag sent to a backend).",
        ],
        [
            "On an authorized rooted lab device, launch the app and record whether it warns, exits, or continues.",
            "Repeat on a stock unrooted device as a baseline.",
            "Document the observed policy only. Do not use this guidance to hide root or bypass the check.",
        ],
    ),
    ("ASSESS-JAILBREAK-DETECTION", "IOS"): _g(
        "Checks for jailbreak indicators (Cydia, Substrate, /var/jb, sshd, apt-get, and similar paths).",
        [
            "In Ghidra/strings, search for cydia, substrate, /var/jb, /Applications/Cydia, /usr/sbin/sshd, apt-get.",
            "Find the calling function and note whether a failed check is fatal or advisory.",
            "Distinguish first-party checks from embedded security SDK strings.",
        ],
        [
            "On an authorized jailbroken lab device, launch the app and record warn / exit / continue behavior.",
            "Repeat on a stock device as a baseline.",
            "Document the policy only; do not treat this as a jailbreak-hide recipe.",
        ],
    ),
    ("ASSESS-FRIDA-DETECTION", "ANDROID"): _g(
        "Looks for Frida / Xposed / instrumentation countermeasures (frida-server, gum-js-loop, port 27042, xposed, substrate).",
        [
            "Search DEX/strings/native for frida, gum-js-loop, LIBFRIDA, frida-server, 27042, xposed, substrate, cynject.",
            "Check native libraries for anti-instrumentation symbols or maps-file scans.",
            "Note whether detection is app-owned or comes from a RASP SDK.",
        ],
        [
            "On an authorized lab device, observe app behavior with and without common instrumentation tools loaded.",
            "Record whether the app refuses to run, degrades, or only logs the condition.",
            "This is a presence check for testers — not a bypass or hooking cookbook.",
        ],
    ),
    ("ASSESS-FRIDA-DETECTION", "IOS"): _g(
        "Looks for Frida / Substrate / Cycript instrumentation countermeasures (FridaGadget, cynject, libsubstrate).",
        [
            "Search Mach-O strings and symbols for frida, cynject, cycript, libsubstrate, FridaGadget.",
            "Inspect imported dylibs for gadget or substrate loaders.",
            "Note whether the check is first-party or a commercial shield.",
        ],
        [
            "On an authorized lab device, compare startup with and without instrumentation frameworks present.",
            "Record warn / exit / continue behavior.",
            "Do not use this as a recipe to hide instrumentation.",
        ],
    ),
    ("ASSESS-DEBUG-DETECTION", "ANDROID"): _g(
        "Checks for debugger detection (Debug.isDebuggerConnected, TracerPid, FLAG_DEBUGGABLE).",
        [
            "In JADX, search for isDebuggerConnected, Debug.isDebuggerConnected, TracerPid, FLAG_DEBUGGABLE.",
            "See whether the result is used to finish the activity, wipe state, or only logged.",
            "Cross-check android:debuggable in the merged manifest (related control ASSESS-DEBUGGABLE-OFF).",
        ],
        [
            "On an authorized debuggable build, attach Android Studio / lldb and record whether the app notices.",
            "Repeat on a release build if one is in scope.",
            "Document detection behavior only; do not provide anti-anti-debug patches.",
        ],
    ),
    ("ASSESS-ANTIDEBUG", "IOS"): _g(
        "Checks for anti-debug primitives (PT_DENY_ATTACH, ptrace, P_TRACED, sysctl/KERN_PROC).",
        [
            "In Ghidra, search for PT_DENY_ATTACH, ptrace, P_TRACED, KERN_PROC, sysctl.",
            "Identify the call site (constructor, +load, or a dedicated anti-tamper function).",
            "Note whether failure is fatal or ignored.",
        ],
        [
            "On an authorized lab device, attempt a debugger attach and record whether the process denies attach or continues.",
            "Compare against a debug-entitled build if available (see get-task-allow).",
            "Inventory only — not a ptrace-bypass guide.",
        ],
    ),
    ("ASSESS-EMULATOR-DETECTION", "ANDROID"): _g(
        "Looks for emulator / QEMU heuristics (goldfish, ranchu, generic_x86, isEmulator, qemu).",
        [
            "Search code and strings for goldfish, ranchu, generic_x86, isEmulator, qemu, and Build.FINGERPRINT / MODEL checks.",
            "See which Build/System properties are read and what happens on a match.",
            "Separate first-party checks from security-SDK strings.",
        ],
        [
            "On an authorized emulator, launch the app and record warn / exit / continue.",
            "Repeat on a physical device as a baseline.",
            "Document the policy; do not provide emulator-hide steps.",
        ],
    ),
    ("ASSESS-INTEGRITY", "ANDROID"): _g(
        "Checks for Play Integrity / SafetyNet / signature verification (IntegrityManager, GET_SIGNATURES, signingInfo).",
        [
            "In JADX, search for PlayIntegrity, SafetyNet, IntegrityManager, Nonce.Builder, PackageManager.GET_SIGNATURES, signingInfo.",
            "Confirm whether the attestation result is validated on a backend (client-only checks are weaker).",
            "Review gradle/manifest for Play Integrity API dependencies.",
        ],
        [
            "On an authorized device, exercise a flow that should require integrity (login, payment) and capture whether a token is requested.",
            "Compare a genuine-device run against an emulator/lab device if both are in scope.",
            "Record pass/fail handling only; do not attempt to forge attestation.",
        ],
    ),
    ("ASSESS-INTEGRITY", "IOS"): _g(
        "Checks for DeviceCheck / App Attest / code-signature validation (DCAppAttest, SecCodeCheckValidity).",
        [
            "Search for DeviceCheck, DCAppAttest, AppAttest, SecCodeCheckValidity.",
            "Check entitlements and Info.plist for App Attest / DeviceCheck usage.",
            "Note whether attestation is sent to a backend or only checked locally.",
        ],
        [
            "On an authorized device, exercise a protected flow and observe whether DeviceCheck/App Attest APIs are invoked.",
            "Record how the app behaves when the OS cannot attest (unsupported device).",
            "Do not attempt to spoof attestation tokens.",
        ],
    ),
    ("ASSESS-SSL-PINNING", "ANDROID"): _g(
        "Looks for certificate / public-key pinning (OkHttp CertificatePinner, Network Security Config pin-set, TrustKit, custom TrustManager).",
        [
            "In JADX, search for CertificatePinner, TrustKit, SSLPinner, PublicKeyPinning, sha256/, custom X509TrustManager + checkServerTrusted.",
            "Open res/xml/network_security_config.xml (or equivalent) for <pin-set> / pin digest entries.",
            "Note which hosts are pinned and whether debug-overrides are enabled.",
        ],
        [
            "On an authorized lab proxy with a user-installed CA, browse a pinned host and record whether the TLS handshake is rejected.",
            "Repeat without the proxy as a baseline.",
            "This confirms enforcement. Do not ship unpinning scripts or TrustManager patches.",
        ],
    ),
    ("ASSESS-SSL-PINNING", "IOS"): _g(
        "Looks for TrustKit / NSPinnedDomains / custom SecTrustEvaluate pinning.",
        [
            "Search for TrustKit, TSKPinningValidator, NSPinnedDomains, SecTrustEvaluate, pinnedPublicKey, SSLPinning.",
            "Inspect Info.plist for NSPinnedDomains / TrustKit configuration.",
            "Identify which hosts are pinned.",
        ],
        [
            "On an authorized lab proxy with a user-installed CA, hit a pinned host and record whether the connection fails closed.",
            "Repeat without interception as a baseline.",
            "Confirm enforcement only; do not provide unpinning recipes.",
        ],
    ),
    ("ASSESS-CLEARTEXT-BLOCKED", "ANDROID"): _g(
        "Checks whether cleartext HTTP is blocked (android:usesCleartextTraffic=false / network security config).",
        [
            "Read the merged AndroidManifest for android:usesCleartextTraffic.",
            "Inspect network security config for cleartextTrafficPermitted and domain exceptions.",
            "Search code for http:// URLs or cleartext OkHttp configurations that would contradict the flag.",
        ],
        [
            "On an authorized device, attempt a known HTTP (non-TLS) endpoint the app might call and record whether it is blocked.",
            "Review traffic in a lab proxy for any plaintext HTTP.",
            "Document exceptions (debug builds, specific domains) rather than forcing cleartext.",
        ],
    ),
    ("ASSESS-ATS", "IOS"): _g(
        "Checks App Transport Security posture (NSAppTransportSecurity / NSAllowsArbitraryLoads).",
        [
            "Open Info.plist NSAppTransportSecurity and note NSAllowsArbitraryLoads and per-domain exceptions.",
            "Search strings for ATS exception keys.",
            "List which domains are allowed to use insecure loads, if any.",
        ],
        [
            "On an authorized device, observe whether HTTP URLs fail as ATS would require.",
            "Review lab proxy traffic for plaintext HTTP.",
            "Record exceptions; do not weaken ATS on production builds.",
        ],
    ),
    ("ASSESS-FLAG-SECURE", "ANDROID"): _g(
        "Checks for FLAG_SECURE (blocks screenshots and screen recording of protected windows).",
        [
            "In JADX, search for FLAG_SECURE, setFlags(...FLAG_SECURE), addFlags(...FLAG_SECURE).",
            "Identify which Activities/Windows apply it (login, payments, PII) versus a global Application hook.",
            "Note Compose / WebView / overlay windows that may not inherit the flag.",
        ],
        [
            "On an authorized device, open the sensitive screen and attempt a screenshot / screen recording; record whether the OS blocks it.",
            "Check recent-apps thumbnails for leaked content.",
            "Inventory coverage only; do not provide FLAG_SECURE bypasses.",
        ],
    ),
    ("ASSESS-TOUCH-FILTER", "ANDROID"): _g(
        "Checks overlay / tapjacking hardening (filterTouchesWhenObscured, FILTER_TOUCHES, setOnFilterTouchEventListener).",
        [
            "In JADX, search for filterTouchesWhenObscured, setOnFilterTouchEventListener, FILTER_TOUCHES.",
            "See which critical buttons (login, pay, confirm) set the property.",
            "Review layouts for android:filterTouchesWhenObscured=\"true\".",
        ],
        [
            "On an authorized device, place a lab overlay above a sensitive control and record whether touches are dropped.",
            "Repeat without an overlay as a baseline.",
            "Document the result; do not provide overlay-abuse exploits.",
        ],
    ),
    ("ASSESS-BACKUP-DISABLED", "ANDROID"): _g(
        "Checks whether ADB/cloud backup is disabled (android:allowBackup=false).",
        [
            "Read the merged manifest for android:allowBackup and fullBackupContent / dataExtractionRules.",
            "If backup is allowed, review which files/shared prefs would be included.",
            "Search for BackupAgent implementations.",
        ],
        [
            "On an authorized debug device, try adb backup (where still supported) or device-to-device transfer and record whether app data is excluded.",
            "Inspect Auto Backup / D2D rules on the OS version in scope.",
            "Do not extract other users' backup data; this is a configuration check.",
        ],
    ),
    ("ASSESS-DEBUGGABLE-OFF", "ANDROID"): _g(
        "Checks that a release build is not android:debuggable=true.",
        [
            "Read the merged AndroidManifest for android:debuggable.",
            "Confirm you are looking at the intended release artifact, not a debug variant.",
            "Search for BuildConfig.DEBUG or equivalent runtime branches.",
        ],
        [
            "On the installed build, check ApplicationInfo.FLAG_DEBUGGABLE (or Settings) and record the value.",
            "Attempt a debugger attach only on authorized lab builds and note whether it is allowed.",
            "A production app marked debuggable is a finding; do not exploit it beyond documenting attachability.",
        ],
    ),
    ("ASSESS-GET-TASK-ALLOW-OFF", "IOS"): _g(
        "Checks that the get-task-allow entitlement (debugger attach) is absent on the release binary.",
        [
            "Inspect embedded.mobileprovision / entitlements for get-task-allow.",
            "Confirm the artifact is a distribution build, not a development-signed one.",
            "Search strings for the entitlement key as a secondary signal.",
        ],
        [
            "On an authorized device, note whether a debugger can attach to the production-signed app.",
            "Compare against a development-signed build if both are in scope.",
            "Document entitlement posture only.",
        ],
    ),
    ("ASSESS-NATIVE-HARDENING", "ANDROID"): _g(
        "Inventories ELF hardening on packaged .so files (PIC/DYN, stack canary, stripped symbols).",
        [
            "Use readelf/checksec (or the scanner's NativeLib* resource rows) for PIC, stack canary, and debug symbols on each ABI.",
            "Flag libraries with PIC disabled, missing canaries, or unstripped debug symbols.",
            "Focus on first-party libs; some vendor SDKs ship with weaker flags.",
        ],
        [
            "On an authorized device, confirm which .so files load in the flows you care about.",
            "Record hardening gaps as configuration debt, not as an exploit path.",
            "Do not write memory-corruption PoCs against missing canaries.",
        ],
    ),
    ("ASSESS-PIE", "IOS"): _g(
        "Checks that the Mach-O main binary is a position-independent executable (MH_PIE).",
        [
            "Inspect Mach-O header flags for MH_PIE (the scanner records MH_PIE=0/1).",
            "Repeat for extensions and watch/companion binaries if present.",
            "Modern toolchains default to PIE; an absent flag on a current app is notable.",
        ],
        [
            "Confirm the installed binary matches the analyzed artifact (same slice/arch).",
            "Record PIE as a hardening inventory item, not an exploit prerequisite.",
            "Do not develop ASLR-bypass PoCs from this control.",
        ],
    ),
    ("ASSESS-KEYSTORE", "ANDROID"): _g(
        "Checks for Android Keystore usage (AndroidKeyStore, KeyGenParameterSpec, KeyStore.getInstance).",
        [
            "In JADX, search for AndroidKeyStore, KeyGenParameterSpec, KeyStore.getInstance(\"AndroidKeyStore\").",
            "See whether keys require user authentication / biometrics and whether they are hardware-backed (setIsStrongBoxBacked).",
            "Find what secrets are stored (tokens, DEKs) versus keys that only wrap other material.",
        ],
        [
            "On an authorized device, exercise the crypto/auth flow and confirm Keystore prompts or hardware-backed errors when expected.",
            "After uninstall/reinstall, record whether keys are correctly invalidated.",
            "Do not extract Keystore material; verify usage only.",
        ],
    ),
    ("ASSESS-KEYCHAIN", "IOS"): _g(
        "Checks for Keychain Services usage (SecItemAdd, kSecClassGenericPassword, kSecAttrAccessible).",
        [
            "Search for SecItemAdd/Copy/Update/Delete, kSecClassGenericPassword, kSecAttrAccessible, kSecAccessControl.",
            "Note accessibility (AfterFirstUnlock, WhenUnlockedThisDeviceOnly) and access-control flags.",
            "Identify which items are Keychain-backed versus UserDefaults/files.",
        ],
        [
            "On an authorized device, exercise login/token storage and confirm items appear in Keychain (lab tools / Console) with the expected accessibility.",
            "Reboot and verify items are unavailable until the documented unlock state.",
            "Do not dump other apps' Keychain items; verify this app's usage only.",
        ],
    ),
    ("ASSESS-BIOMETRIC", "ANDROID"): _g(
        "Checks whether the app uses BiometricPrompt / BiometricManager / FingerprintManager to gate sensitive actions.",
        [
            "In JADX, search for BiometricPrompt, BiometricManager, FingerprintManager, and androidx.biometric.",
            "Confirm a CryptoObject / cipher is bound to the prompt when cryptography is involved (not UI-only).",
            "Check the manifest for USE_BIOMETRIC / USE_FINGERPRINT and review copy in strings.xml.",
        ],
        [
            "On an authorized device with biometrics enrolled, trigger the protected flow and confirm a system prompt appears.",
            "Cancel or fail the prompt and confirm the sensitive action does not proceed.",
            "Repeat with biometrics unenrolled and record PIN/password fallback or denial. Do not spoof biometrics.",
        ],
    ),
    ("ASSESS-BIOMETRIC", "IOS"): _g(
        "Checks whether the app uses LocalAuthentication (LAContext / evaluatePolicy) for Face ID / Touch ID.",
        [
            "In Ghidra/class-dump, search for LocalAuthentication, LAContext, evaluatePolicy, biometryType.",
            "Check Info.plist for NSFaceIDUsageDescription.",
            "See whether the policy is deviceOwnerAuthenticationWithBiometrics versus deviceOwnerAuthentication (passcode fallback).",
        ],
        [
            "On an authorized device with biometrics enrolled, trigger the protected flow and confirm the system prompt.",
            "Fail or cancel and confirm the action is blocked.",
            "Test with biometrics unavailable and record fallback. Do not spoof Face ID / Touch ID.",
        ],
    ),
    ("ASSESS-A11Y-DEFENSE", "ANDROID"): _g(
        "Looks for defenses against accessibility / autoclicker abuse (overlay filters, FLAG_SECURE, anti-overlay copy) versus mere AccessibilityService usage.",
        [
            "Search for AccessibilityService, BIND_ACCESSIBILITY_SERVICE, canRequestTouchExplorationMode (capability) versus filterTouchesWhenObscured, FLAG_SECURE, anti-overlay, autoclick (defense).",
            "Review whether the app itself is an accessibility service (higher risk) or only defends against third-party services.",
            "Check sensitive windows for overlay/touch filters.",
        ],
        [
            "On an authorized device, enable a lab accessibility service you control and record whether sensitive actions can be driven automatically.",
            "Note any in-app warnings when an accessibility service is enabled.",
            "Do not build autoclicker malware; record the app's defense posture only.",
        ],
    ),
    ("ASSESS-SCREEN-CAPTURE", "IOS"): _g(
        "Checks screen-capture / secure-text protections (isSecureTextEntry, UIScreenCapturedDidChange).",
        [
            "Search for isSecureTextEntry, UITextFieldSecure, screen capture, UIScreenCapturedDidChange.",
            "Identify which fields and view controllers hide content when captured.",
            "Review snapshot/blur logic in applicationWillResignActive if present.",
        ],
        [
            "On an authorized device, screenshot/record the sensitive screen and note whether content is hidden or a warning appears.",
            "Background the app and check the app-switcher snapshot for leaked PII.",
            "Inventory only; do not provide capture bypasses.",
        ],
    ),
    ("ASSESS-SECURITY-SDK", _ANY): _g(
        "Inventories third-party security / RASP SDKs (RootBeer, Promon, Talsec, Appdome, DexGuard, and similar markers).",
        [
            "Search strings, package names, and native libs for known security-SDK fingerprints (same vendor list as obfuscator-vendor, plus RootBeer).",
            "List each distinct product detected; do not assume it is correctly configured.",
            "Map SDK classes to the protections they claim (root, tamper, pinning) for follow-up controls.",
        ],
        [
            "On an authorized device, watch startup logs for SDK initialization banners or license checks.",
            "Exercise a flow the SDK is supposed to protect and record whether it visibly enforces anything.",
            "Do not reverse or crack commercial RASP; inventory presence and obvious runtime behavior only.",
        ],
    ),
}


def fallback(control_id: Optional[str] = None, title: Optional[str] = None) -> dict:
    label = (title or "").strip() or (control_id or "").strip() or "this control"
    return _g(
        "Inventories whether "
        + label
        + " appears implemented in this build. "
        + "Absence of static signals does not prove the control is missing on packed or heavily obfuscated apps.",
        _FALLBACK_STATIC,
        _FALLBACK_DYNAMIC,
    )


def lookup(
    control_id: Optional[str],
    platform: Optional[str] = None,
    title: Optional[str] = None,
) -> dict:
    cid = (control_id or "").strip()
    if not cid:
        return fallback(control_id, title)
    plat = (platform or "").strip().upper()
    if plat and (cid, plat) in _GUIDES:
        return dict(_GUIDES[(cid, plat)])
    if (cid, _ANY) in _GUIDES:
        return dict(_GUIDES[(cid, _ANY)])
    for (gid, _), guide in _GUIDES.items():
        if gid == cid:
            return dict(guide)
    return fallback(cid, title)


def enrich_assessment(row: dict) -> dict:
    """Attach catalog fields without mutating SQLite-backed keys."""
    guide = lookup(row.get("control_id"), row.get("platform"), row.get("title"))
    out = dict(row)
    out["summary"] = guide["summary"]
    out["static_checks"] = list(guide["static_checks"])
    out["dynamic_checks"] = list(guide["dynamic_checks"])
    return out
