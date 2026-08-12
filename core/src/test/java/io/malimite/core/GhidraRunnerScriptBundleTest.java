package io.malimite.core;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.jar.JarFile;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GhidraRunnerScriptBundleTest {

    @Test void sanitizeProjectNameStripsSpacesAndSpecialChars() {
        assertEquals("Captain_Nohook", GhidraRunner.sanitizeProjectName("Captain Nohook"));
        assertEquals("My_App", GhidraRunner.sanitizeProjectName("My App!"));
        assertEquals("binary", GhidraRunner.sanitizeProjectName("   "));
        assertEquals("binary", GhidraRunner.sanitizeProjectName(null));
        assertEquals("App_v1.2", GhidraRunner.sanitizeProjectName("App_v1.2"));
    }

    @Test void bundleOrgJsonWritesJarWithJsonObject(@TempDir Path tmp) throws Exception {
        GhidraRunner.bundleOrgJsonForScript(tmp);
        Path jar = tmp.resolve("json.jar");
        assertTrue(Files.isRegularFile(jar), "json.jar should be created");
        assertTrue(Files.size(jar) > 100, "json.jar should not be empty");
        try (JarFile jf = new JarFile(jar.toFile())) {
            assertTrue(jf.stream().anyMatch(e -> e.getName().equals("org/json/JSONObject.class")),
                    "json.jar must contain org.json.JSONObject");
            assertTrue(jf.stream().anyMatch(e -> e.getName().equals("org/json/JSONString.class")),
                    "json.jar must contain org.json.JSONString (JSONObject.toString needs it)");
        }
    }

    @Test void extractPackageToJarCopiesOnlyRequestedPrefix(@TempDir Path tmp) throws Exception {
        Path source = Path.of(org.json.JSONObject.class.getProtectionDomain()
                .getCodeSource().getLocation().toURI());
        // When running from a fat jar / classes dir this may be a directory — skip gracefully
        if (!Files.isRegularFile(source)) {
            GhidraRunner.bundleOrgJsonForScript(tmp);
            assertTrue(Files.exists(tmp.resolve("json.jar")));
            return;
        }
        Path dest = tmp.resolve("thin-json.jar");
        GhidraRunner.extractPackageToJar(source, "org/json/", dest);
        assertTrue(Files.size(dest) > 0);
        try (JarFile jf = new JarFile(dest.toFile())) {
            assertTrue(jf.stream().anyMatch(e -> e.getName().startsWith("org/json/")));
            assertFalse(jf.stream().anyMatch(e -> e.getName().startsWith("io/malimite/")));
        }
    }
}
