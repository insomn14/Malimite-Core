package io.malimite.core;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class AndroidNativeLibraryDefinitionsTest {

    @Test void stemStripsLibSoAndSeparators() {
        assertEquals("objectbox", AndroidNativeLibraryDefinitions.stem("libobjectbox.so"));
        assertEquals("bugsnagndk", AndroidNativeLibraryDefinitions.stem("libbugsnag-ndk.so"));
        assertEquals("nativelib", AndroidNativeLibraryDefinitions.stem("libnative-lib.so"));
        assertEquals("toolchecker", AndroidNativeLibraryDefinitions.stem("libtoolChecker.so"));
        assertEquals("foodstore", AndroidNativeLibraryDefinitions.stem("lib/arm64-v8a/libfoodstore.so"));
    }

    @Test void ndkSystemLibsAreRecognized() {
        assertTrue(AndroidNativeLibraryDefinitions.isNdkSystemLib("libc.so"));
        assertTrue(AndroidNativeLibraryDefinitions.isNdkSystemLib("liblog.so"));
        assertFalse(AndroidNativeLibraryDefinitions.isNdkSystemLib("libfoodstore.so"));
    }

    @Test void vendorLibsAreGenericThirdParty() {
        assertTrue(AndroidNativeLibraryDefinitions.isVendorLib("libobjectbox.so"));
        assertTrue(AndroidNativeLibraryDefinitions.isVendorLib("libbugsnag-ndk.so"));
        assertTrue(AndroidNativeLibraryDefinitions.isVendorLib("libavif.so"));
        assertFalse(AndroidNativeLibraryDefinitions.isVendorLib("libfoodstore.so"));
        assertFalse(AndroidNativeLibraryDefinitions.isVendorLib("libdigitalbank.so"));
        assertFalse(AndroidNativeLibraryDefinitions.isVendorLib("libtoolChecker.so"));
    }

    @Test void securitySdkAllowlistIsNarrow() {
        assertTrue(AndroidNativeLibraryDefinitions.isSecuritySdkLib("libtoolChecker.so"));
        assertTrue(AndroidNativeLibraryDefinitions.isSecuritySdkLib("libtalsec.so"));
        assertTrue(AndroidNativeLibraryDefinitions.isSecuritySdkLib("libconscrypt_jni.so"));
        assertFalse(AndroidNativeLibraryDefinitions.isSecuritySdkLib("libobjectbox.so"));
        assertFalse(AndroidNativeLibraryDefinitions.isSecuritySdkLib("libfoodstore.so"));
    }

    @Test void genericAppJniHeuristic() {
        assertTrue(AndroidNativeLibraryDefinitions.isGenericAppJni("libnative-lib.so"));
        assertTrue(AndroidNativeLibraryDefinitions.isGenericAppJni("libjni.so"));
        assertFalse(AndroidNativeLibraryDefinitions.isGenericAppJni("libobjectbox.so"));
        assertFalse(AndroidNativeLibraryDefinitions.isGenericAppJni("libfoodstore.so"));
    }
}
