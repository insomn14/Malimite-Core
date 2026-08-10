package io.malimite.core;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.*;

class SarifExporterTest {

    private static AnalysisReport sampleReport() {
        return new AnalysisReport(
                "test-scan-id",
                "TestApp",
                "com.example.test",
                true, false,
                List.of("ARM64"),
                1234L,
                3, 10, 5,
                Map.of("ViewController", List.of("viewDidLoad", "buttonTapped")),
                List.of(
                        new AnalysisReport.StringEntry("0x1000", "api_key=supersecret", "__TEXT", "str1"),
                        new AnalysisReport.StringEntry("0x1010", "Hello", "__TEXT", "str2")
                ),
                List.of("Global.main"),
                "ABCDE12345",
                "MyProfile",
                "2026-12-31",
                List.of(new AnalysisReport.LlmFinding(
                        "buttonTapped", "ViewController", "FIND_VULNS",
                        "HIGH: SQL injection risk in user input handling")),
                List.of(),
                "/tmp/test.sqlite",
                "IOS"
        );
    }

    @Test void writesSarifFile(@TempDir Path tmp) throws Exception {
        Path sarif = SarifExporter.export(sampleReport(), tmp);
        assertTrue(Files.exists(sarif));
        String content = Files.readString(sarif);
        assertTrue(content.contains("\"version\": \"2.1.0\""));
        assertTrue(content.contains("Malimite"));
    }

    @Test void containsEntryPointResult(@TempDir Path tmp) throws Exception {
        Path sarif = SarifExporter.export(sampleReport(), tmp);
        String content = Files.readString(sarif);
        assertTrue(content.contains("MALIMITE001"));
        assertTrue(content.contains("Global.main"));
    }

    @Test void flagsSuspiciousString(@TempDir Path tmp) throws Exception {
        Path sarif = SarifExporter.export(sampleReport(), tmp);
        String content = Files.readString(sarif);
        assertTrue(content.contains("MALIMITE002"));
        assertTrue(content.contains("api_key"));
    }

    @Test void includesLlmVulnFinding(@TempDir Path tmp) throws Exception {
        Path sarif = SarifExporter.export(sampleReport(), tmp);
        String content = Files.readString(sarif);
        assertTrue(content.contains("MALIMITE003"));
        assertTrue(content.contains("SQL injection"));
    }
}
