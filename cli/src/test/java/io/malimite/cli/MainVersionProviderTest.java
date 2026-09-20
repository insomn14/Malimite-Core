package io.malimite.cli;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class MainVersionProviderTest {

    @Test
    void fallsBackForMissingManifestVersion() {
        assertEquals("malimite (development build)",
                Main.ManifestVersionProvider.versionLine(null));
        assertEquals("malimite (development build)",
                Main.ManifestVersionProvider.versionLine("  "));
    }

    @Test
    void formatsManifestVersion() {
        assertEquals("malimite 1.2.3",
                Main.ManifestVersionProvider.versionLine("1.2.3"));
    }
}
