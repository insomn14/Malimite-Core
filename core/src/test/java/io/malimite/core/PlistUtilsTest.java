package io.malimite.core;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class PlistUtilsTest {

    @Test void detectsXmlPlist() {
        byte[] xml = "<?xml version=\"1.0\"?><plist version=\"1.0\"/>".getBytes();
        assertFalse(PlistUtils.isBinaryPlist(xml));
    }

    @Test void detectsBinaryPlist() {
        byte[] bin = "bplist00somedata".getBytes();
        assertTrue(PlistUtils.isBinaryPlist(bin));
    }

    @Test void emptyBytesNotBinary() {
        assertFalse(PlistUtils.isBinaryPlist(new byte[0]));
        assertFalse(PlistUtils.isBinaryPlist(new byte[3]));
    }
}
