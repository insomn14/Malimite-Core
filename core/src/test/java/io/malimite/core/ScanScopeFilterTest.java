package io.malimite.core;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * First-party matching is derived from each scan's applicationId / bundle id.
 * These fixtures are two unrelated real-world-style ids — not a hardcoded brand list.
 */
class ScanScopeFilterTest {

    static final String FOODSTORE = "com.mobilehackinglab.foodstore";
    static final String DIGITALBANK = "id.co.bankbkemobile.digitalbank";

    @Test void androidLibrarySkipDoesNotFalsePositiveOnAppAndroidSegment() {
        assertTrue(AndroidLibraryDefinitions.shouldSkip("android.app.Activity"));
        assertTrue(AndroidLibraryDefinitions.shouldSkip("androidx.appcompat.app.AppCompatActivity"));
        assertTrue(AndroidLibraryDefinitions.shouldSkip("okhttp3.OkHttpClient"));
        assertFalse(AndroidLibraryDefinitions.shouldSkip("com.example.foo.MainActivity"));
        assertFalse(AndroidLibraryDefinitions.shouldSkip("com.mobilehackinglab.foodstore.MainActivity"));
        assertFalse(AndroidLibraryDefinitions.shouldSkip("com.scottyab.rootbeer.RootBeer"));
    }

    @Test void firstPartyPrefixesDerivedFromEachApplicationId() {
        List<String> food = ScanScopeFilter.firstPartyPrefixes(FOODSTORE);
        assertEquals(List.of(FOODSTORE, "com.mobilehackinglab"), food);
        assertTrue(ScanScopeFilter.matchesAnyPrefix("com.mobilehackinglab.foodstore.MainActivity", food));
        assertTrue(ScanScopeFilter.matchesAnyPrefix("com.mobilehackinglab.sdk.Client", food));
        assertFalse(ScanScopeFilter.matchesAnyPrefix("com.mobilehackinglabx.Other", food));
        assertFalse(ScanScopeFilter.matchesAnyPrefix("io.objectbox.BoxStore", food));
        assertFalse(ScanScopeFilter.matchesAnyPrefix("id.co.bankbkemobile.digitalbank.Home", food));

        List<String> bank = ScanScopeFilter.firstPartyPrefixes(DIGITALBANK);
        assertEquals(List.of(DIGITALBANK, "id.co.bankbkemobile"), bank);
        assertTrue(ScanScopeFilter.matchesAnyPrefix("id.co.bankbkemobile.digitalbank.HomeActivity", bank));
        assertTrue(ScanScopeFilter.matchesAnyPrefix("id.co.bankbkemobile.sdk.Api", bank));
        assertFalse(ScanScopeFilter.matchesAnyPrefix("id.co.bankbkemobilex.Other", bank));
        assertFalse(ScanScopeFilter.matchesAnyPrefix("com.mobilehackinglab.foodstore.MainActivity", bank));
    }

    @Test void threeSegmentIdUsesParentPrefix() {
        List<String> p = ScanScopeFilter.firstPartyPrefixes("com.example.app");
        assertTrue(p.contains("com.example.app"));
        assertTrue(p.contains("com.example"));
        assertTrue(ScanScopeFilter.matchesAnyPrefix("com.example.sdk.Api", p));
    }

    @Test void twoSegmentIdDoesNotCollapseToTld() {
        List<String> p = ScanScopeFilter.firstPartyPrefixes("example.app");
        assertEquals(List.of("example.app"), p);
        assertFalse(ScanScopeFilter.matchesAnyPrefix("example.other", p));
    }

    @Test void fastScanIsApplicationIdSpecificAndSkipsVendorJava() {
        ScanScopeFilter food = ScanScopeFilter.from(
                LlmMode.SUMMARIZE, FOODSTORE, PackagePlatform.ANDROID, List.of());
        ScanScopeFilter bank = ScanScopeFilter.from(
                LlmMode.SUMMARIZE, DIGITALBANK, PackagePlatform.ANDROID, List.of());

        assertTrue(food.includeClass("com.mobilehackinglab.foodstore.MainActivity"));
        assertTrue(food.includeClass("com.mobilehackinglab.sdk.PayClient"));
        assertFalse(food.includeClass("id.co.bankbkemobile.digitalbank.HomeActivity"));
        assertFalse(food.includeClass("io.objectbox.BoxStore"));
        assertFalse(food.includeClass("com.bugsnag.android.Client"));
        assertFalse(food.includeClass("com.scottyab.rootbeer.RootBeer"));
        assertFalse(food.includeClass("androidx.appcompat.app.AppCompatActivity"));

        assertTrue(bank.includeClass("id.co.bankbkemobile.digitalbank.HomeActivity"));
        assertTrue(bank.includeClass("id.co.bankbkemobile.sdk.Transfer"));
        assertFalse(bank.includeClass("com.mobilehackinglab.foodstore.MainActivity"));
        assertFalse(bank.includeClass("io.objectbox.BoxStore"));
    }

    @Test void extraPrefixIsHonoredInFastScan() {
        ScanScopeFilter fast = ScanScopeFilter.from(
                LlmMode.SUMMARIZE, "com.other.app", PackagePlatform.ANDROID,
                List.of("com.example.shared"));
        assertTrue(fast.includeClass("com.example.shared.Crypto"));
        assertFalse(fast.includeClass("io.objectbox.Box"));
    }

    @Test void offensiveAddsSecuritySdkButNotGenericThirdParty() {
        ScanScopeFilter off = ScanScopeFilter.from(
                LlmMode.OFFENSIVE, FOODSTORE, PackagePlatform.ANDROID, List.of());
        assertTrue(off.includeClass("com.mobilehackinglab.foodstore.MainActivity"));
        assertTrue(off.includeClass("com.scottyab.rootbeer.RootBeer"));
        assertTrue(off.includeClass("com.talsec.security.Talsec"));
        assertFalse(off.includeClass("io.objectbox.BoxStore"));
        assertFalse(off.includeClass("com.bugsnag.android.Client"));
        assertFalse(off.includeClass("id.co.bankbkemobile.digitalbank.HomeActivity"));
    }

    @Test void fullScanIncludesThirdParty() {
        ScanScopeFilter full = ScanScopeFilter.from(
                LlmMode.FIND_VULNS, DIGITALBANK, PackagePlatform.ANDROID, List.of());
        assertTrue(full.isAll());
        assertTrue(full.includeClass("io.objectbox.BoxStore"));
        assertTrue(full.includeNativeLib("libobjectbox.so"));
        assertTrue(full.includeClass("com.mobilehackinglab.foodstore.MainActivity"));
    }

    @Test void nativeLibsMatchTokensFromEachApplicationId() {
        ScanScopeFilter food = ScanScopeFilter.from(
                LlmMode.SUMMARIZE, FOODSTORE, PackagePlatform.ANDROID, List.of());
        ScanScopeFilter bank = ScanScopeFilter.from(
                LlmMode.SUMMARIZE, DIGITALBANK, PackagePlatform.ANDROID, List.of());
        ScanScopeFilter off = ScanScopeFilter.from(
                LlmMode.OFFENSIVE, FOODSTORE, PackagePlatform.ANDROID, List.of());

        assertTrue(food.includeNativeLib("libfoodstore.so"));
        assertTrue(food.includeNativeLib("libmobilehackinglab.so"));
        assertTrue(food.includeNativeLib("libnative-lib.so"));
        assertFalse(food.includeNativeLib("libdigitalbank.so"));
        assertFalse(food.includeNativeLib("libbankbkemobile.so"));
        assertFalse(food.includeNativeLib("libobjectbox.so"));
        assertFalse(food.includeNativeLib("libbugsnag-ndk.so"));
        assertFalse(food.includeNativeLib("libconscrypt_jni.so"));
        assertFalse(food.includeNativeLib("libavif.so"));
        assertFalse(food.includeNativeLib("libtoolChecker.so"));

        assertTrue(bank.includeNativeLib("libdigitalbank.so"));
        assertTrue(bank.includeNativeLib("libbankbkemobile.so"));
        assertTrue(bank.includeNativeLib("libnative-lib.so"));
        assertFalse(bank.includeNativeLib("libfoodstore.so"));
        assertFalse(bank.includeNativeLib("libobjectbox.so"));

        assertTrue(off.includeNativeLib("libfoodstore.so"));
        assertTrue(off.includeNativeLib("libtoolChecker.so"));
        assertTrue(off.includeNativeLib("libconscrypt_jni.so"));
        assertTrue(off.includeNativeLib("libtalsec.so"));
        assertFalse(off.includeNativeLib("libobjectbox.so"));
        assertFalse(off.includeNativeLib("libavif.so"));
        assertFalse(off.includeNativeLib("libdigitalbank.so"));
    }

    @Test void nativeFunctionClassUsesSoNameFromApplicationId() {
        ScanScopeFilter food = ScanScopeFilter.from(
                LlmMode.SUMMARIZE, FOODSTORE, PackagePlatform.ANDROID, List.of());
        var inScope = new SqliteStore.DecompilationResult(
                "JNI_OnLoad", "native:libfoodstore.so/entry", "int JNI_OnLoad(){}", FOODSTORE);
        var otherApp = new SqliteStore.DecompilationResult(
                "JNI_OnLoad", "native:libdigitalbank.so/entry", "int JNI_OnLoad(){}", FOODSTORE);
        var vendor = new SqliteStore.DecompilationResult(
                "obx_query", "native:libobjectbox.so/query", "void q(){}", FOODSTORE);
        assertTrue(food.includeFunction(inScope));
        assertFalse(food.includeFunction(otherApp));
        assertFalse(food.includeFunction(vendor));
    }

    @Test void sanitizePackagePrefixRejectsPaths() {
        assertEquals("com.example.shared", ScanScopeFilter.sanitizePackagePrefix("com.example.shared"));
        assertEquals("com.example.shared", ScanScopeFilter.sanitizePackagePrefix("com.example.shared."));
        assertNull(ScanScopeFilter.sanitizePackagePrefix("../etc/passwd"));
        assertNull(ScanScopeFilter.sanitizePackagePrefix("com/example"));
        assertNull(ScanScopeFilter.sanitizePackagePrefix("com.example; rm -rf"));
        assertNull(ScanScopeFilter.sanitizePackagePrefix(""));
        assertNull(ScanScopeFilter.sanitizePackagePrefix(null));
    }

    @Test void brandTokensComeFromApplicationIdNotAHardcodedList() {
        assertEquals(List.of("mobilehackinglab", "foodstore"),
                ScanScopeFilter.brandTokens(FOODSTORE));
        assertEquals(List.of("bankbkemobile", "digitalbank"),
                ScanScopeFilter.brandTokens(DIGITALBANK));
        assertEquals(List.of("example"), ScanScopeFilter.brandTokens("com.example.foo.staging"));
    }

    @Test void iosSkipsKnownPodsForAnyBundleId() {
        ScanScopeFilter food = ScanScopeFilter.from(
                LlmMode.SUMMARIZE, FOODSTORE, PackagePlatform.IOS, List.of());
        ScanScopeFilter bank = ScanScopeFilter.from(
                LlmMode.SUMMARIZE, DIGITALBANK, PackagePlatform.IOS, List.of());
        assertTrue(food.includeClass("AppDelegate"));
        assertTrue(food.includeClass("FoodStoreRootDetector"));
        assertTrue(bank.includeClass("DigitalBankAppDelegate"));
        assertFalse(food.includeClass("Alamofire.Session"));
        assertFalse(bank.includeClass("BugsnagClient"));
    }
}
