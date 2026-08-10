package io.malimite.core;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses embedded.mobileprovision files.
 *
 * A .mobileprovision file is CMS-signed data with an XML plist embedded verbatim
 * in the payload. We locate it by scanning for the XML header — no BouncyCastle
 * required for the Phase 3 use case (we only need the plist content, not sig verification).
 */
public final class MobileProvision {

    private static final Logger log = LoggerFactory.getLogger(MobileProvision.class);
    private static final Pattern TEAM_ID_PATTERN =
            Pattern.compile("<key>TeamIdentifier</key>\\s*<array>\\s*<string>([^<]+)</string>");
    private static final Pattern APP_ID_PATTERN =
            Pattern.compile("<key>application-identifier</key>\\s*<string>([^<]+)</string>");
    private static final Pattern NAME_PATTERN =
            Pattern.compile("<key>Name</key>\\s*<string>([^<]+)</string>");
    private static final Pattern EXPIRY_PATTERN =
            Pattern.compile("<key>ExpirationDate</key>\\s*<date>([^<]+)</date>");

    private MobileProvision() {}

    /** Extracts the embedded XML plist from CMS-signed mobileprovision bytes. */
    public static String extractXML(byte[] data) {
        // Scan for embedded XML — safe because the plist is literally embedded in the CMS payload
        String raw = new String(data, StandardCharsets.ISO_8859_1);
        int start = raw.indexOf("<?xml");
        int end   = raw.indexOf("</plist>");
        if (start < 0 || end < 0) return null;
        return raw.substring(start, end + "</plist>".length());
    }

    /** Parsed signing information from a .mobileprovision file. */
    public record ProvisionInfo(String teamId, String appId, String profileName, String expiryDate) {}

    /**
     * Parses key fields from mobileprovision bytes.
     * Returns {@code null} if the file cannot be read.
     */
    public static ProvisionInfo parse(byte[] data) {
        try {
            String xml = extractXML(data);
            if (xml == null) {
                log.warn("Could not extract XML from mobileprovision");
                return null;
            }
            return new ProvisionInfo(
                    firstGroup(TEAM_ID_PATTERN, xml),
                    firstGroup(APP_ID_PATTERN, xml),
                    firstGroup(NAME_PATTERN, xml),
                    firstGroup(EXPIRY_PATTERN, xml));
        } catch (Exception e) {
            log.warn("Failed to parse mobileprovision", e);
            return null;
        }
    }

    private static String firstGroup(Pattern p, String text) {
        Matcher m = p.matcher(text);
        return m.find() ? m.group(1).trim() : null;
    }
}
