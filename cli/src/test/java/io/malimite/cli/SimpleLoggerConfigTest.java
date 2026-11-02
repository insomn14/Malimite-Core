package io.malimite.cli;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Locks in that the fat JAR's bundled {@code simplelogger.properties} (cli/src/main/resources/)
 * turns on timestamps for every log line — without it, slf4j-simple's default
 * ("[thread] LEVEL logger - message") has no time prefix, making it impossible to tell how long
 * a step like one LLM enrichment call took just from analysis.log. The web service's Log tab and
 * analysis.log are both an unmodified passthrough of this process's stdout/stderr (see
 * web/app/scanner.py's _run()), so this one resource file is the only place that format is set.
 */
class SimpleLoggerConfigTest {

    @Test void bundledConfigEnablesTimestampsWithTimeOnlyFormat() throws IOException {
        Properties props = new Properties();
        try (InputStream in = getClass().getClassLoader().getResourceAsStream("simplelogger.properties")) {
            assertNotNull(in, "simplelogger.properties must be on the classpath (cli/src/main/resources/)");
            props.load(in);
        }
        assertEquals("true", props.getProperty("org.slf4j.simpleLogger.showDateTime"),
                "log lines must be timestamped");
        assertEquals("HH:mm:ss.SSS", props.getProperty("org.slf4j.simpleLogger.dateTimeFormat"),
                "time-only format — scans run in minutes, not across midnight");
    }
}
