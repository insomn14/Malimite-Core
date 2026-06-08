package io.mailmite.core;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/** Cheap pre-flight checks so we don't waste a Ghidra spawn on garbage. */
public final class IpaValidator {

    private IpaValidator() {}

    public static void validate(Path ipa) throws IOException {
        if (!Files.exists(ipa)) throw new IOException("IPA not found: " + ipa);
        if (Files.size(ipa) < 1024) throw new IOException("IPA suspiciously small");

        // Magic PK\x03\x04 already enforced by ZipFile constructor.
        try (ZipFile zf = new ZipFile(ipa.toFile())) {
            boolean ok = zf.stream()
                    .map(ZipEntry::getName)
                    .anyMatch(n -> n.startsWith("Payload/") && n.contains(".app/"));
            if (!ok) throw new IOException("Not an IPA: missing Payload/*.app/");
        }
    }
}
