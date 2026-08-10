package io.malimite.core;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class BinaryIdentityTest {

    @Test void androidNativeDisablesObjCAndSetsNamespace() {
        BinaryIdentity id = BinaryIdentity.forAndroidNativeLib("com.example.app", "libnative.so");
        assertEquals("com.example.app", id.executableName());
        assertFalse(id.isSwift());
        assertFalse(id.enableObjectiveCAnalyzer());
        assertEquals("native:libnative.so", id.classNamespacePrefix());
        assertFalse(id.libraryPrefixes().isEmpty());
    }

    @Test void androidNativeDefaultLibName() {
        BinaryIdentity id = BinaryIdentity.forAndroidNativeLib("com.app", null);
        assertEquals("native:libunknown.so", id.classNamespacePrefix());
    }
}
