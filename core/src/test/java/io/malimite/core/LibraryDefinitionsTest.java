package io.malimite.core;

import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class LibraryDefinitionsTest {

    @Test void activeLibrariesIncludeBothAppleFrameworksAndThirdPartySdks() {
        List<String> active = LibraryDefinitions.getActiveLibraries(new CoreConfig(Path.of("/opt/ghidra")));
        assertTrue(active.contains("Foundation"));     // Apple framework
        assertTrue(active.contains("Alamofire"));      // third-party SDK
        assertTrue(active.contains("FirebaseAuth"));
    }

    @Test void thirdPartySdksAvoidGenericWordsThatCouldCollideWithAppCode() {
        List<String> sdks = LibraryDefinitions.getThirdPartySdks();
        // Deliberately excluded: too generic, likely to prefix-match a first-party class name.
        assertFalse(sdks.contains("Branch"));
        assertFalse(sdks.contains("Segment"));
    }
}
