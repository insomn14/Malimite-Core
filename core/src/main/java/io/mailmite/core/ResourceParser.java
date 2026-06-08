package io.mailmite.core;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Parses resource files inside an extracted IPA bundle and stores readable strings
 * in the SqliteStore's ResourceStrings table.
 *
 * Port of Malimite's ResourceParser.java — static SQLiteDBHandler replaced with
 * instance SqliteStore; logging replaced with SLF4J.
 */
public final class ResourceParser {

    private static final Logger log = LoggerFactory.getLogger(ResourceParser.class);

    private static final List<Pattern> RESOURCE_PATTERNS = Arrays.asList(
            Pattern.compile(".*\\.plist$"),
            Pattern.compile(".*\\.strings$"),
            Pattern.compile(".*\\.json$"),
            Pattern.compile(".*\\.xml$"),
            Pattern.compile(".*\\.mobileprovision$"),
            Pattern.compile(".*\\.storyboardc$"),
            Pattern.compile(".*\\.xcassets$"),
            Pattern.compile(".*\\.nib$"),
            Pattern.compile(".*\\.xib$")
    );

    private final SqliteStore store;

    public ResourceParser(SqliteStore store) {
        this.store = store;
    }

    public static boolean isResource(String fileName) {
        for (Pattern p : RESOURCE_PATTERNS)
            if (p.matcher(fileName).matches()) return true;
        return false;
    }

    public void parseResourceForStrings(InputStream inputStream, String fileName) {
        try {
            ByteArrayOutputStream buf = new ByteArrayOutputStream();
            byte[] chunk = new byte[4096];
            int n;
            while ((n = inputStream.read(chunk, 0, chunk.length)) != -1)
                buf.write(chunk, 0, n);
            byte[] bytes = buf.toByteArray();

            String content;
            if (fileName.endsWith(".plist")) {
                content = PlistUtils.isBinaryPlist(bytes)
                        ? PlistUtils.decodeBinaryPropertyList(bytes)
                        : new String(bytes, StandardCharsets.UTF_8);
            } else if (fileName.endsWith(".mobileprovision")) {
                content = MobileProvision.extractXML(bytes);
            } else {
                content = new String(bytes, StandardCharsets.UTF_8);
            }

            if (content == null) return;

            try (BufferedReader reader = new BufferedReader(new StringReader(content))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    if (line.trim().isEmpty()) continue;
                    for (String segment : line.split("[^\\p{Print}]+")) {
                        String s = segment.trim();
                        if (!s.isEmpty() && s.replaceAll("\\s+", "").length() > 4) {
                            store.insertResourceString(fileName, s, resourceType(fileName));
                        }
                    }
                }
            }
            log.debug("Parsed resource: {}", fileName);
        } catch (IOException e) {
            log.warn("Error reading resource file {}: {}", fileName, e.getMessage());
        } catch (Exception e) {
            log.warn("Error processing resource file {}: {}", fileName, e.getMessage());
        }
    }

    private static String resourceType(String fileName) {
        if (fileName.endsWith(".plist"))           return "plist";
        if (fileName.endsWith(".strings"))         return "strings";
        if (fileName.endsWith(".json"))            return "json";
        if (fileName.endsWith(".xml"))             return "xml";
        if (fileName.endsWith(".mobileprovision")) return "mobileprovision";
        if (fileName.endsWith(".storyboardc"))     return "storyboard";
        if (fileName.endsWith(".xcassets"))        return "assets";
        if (fileName.endsWith(".nib"))             return "nib";
        return "unknown";
    }
}
