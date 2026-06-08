package io.mailmite.core;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class MobileProvisionTest {

    private static final String SAMPLE_XML =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
        "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\">\n" +
        "<plist version=\"1.0\"><dict>\n" +
        "<key>Name</key><string>MyAppProfile</string>\n" +
        "<key>TeamIdentifier</key><array><string>ABCDE12345</string></array>\n" +
        "<key>application-identifier</key><string>ABCDE12345.com.example.app</string>\n" +
        "<key>ExpirationDate</key><date>2026-12-31T00:00:00Z</date>\n" +
        "</dict></plist>";

    @Test void extractXmlFromEmbeddedPayload() {
        // Simulate mobileprovision: garbage + XML + garbage
        String raw = "CMSPAYLOAD" + SAMPLE_XML + "TRAILERBYTES";
        byte[] bytes = raw.getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);
        String extracted = MobileProvision.extractXML(bytes);
        assertNotNull(extracted);
        assertTrue(extracted.contains("<?xml"));
        assertTrue(extracted.contains("</plist>"));
    }

    @Test void parseExtractsFields() {
        String raw = "CMSPAYLOAD" + SAMPLE_XML + "TRAILERBYTES";
        byte[] bytes = raw.getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);
        MobileProvision.ProvisionInfo info = MobileProvision.parse(bytes);
        assertNotNull(info);
        assertEquals("ABCDE12345", info.teamId());
        assertEquals("MyAppProfile", info.profileName());
        assertEquals("ABCDE12345.com.example.app", info.appId());
        assertEquals("2026-12-31T00:00:00Z", info.expiryDate());
    }

    @Test void parseReturnsNullForGarbage() {
        assertNull(MobileProvision.parse("notamobileprovision".getBytes()));
    }
}
