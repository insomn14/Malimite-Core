package io.mailmite.watcher;

import io.mailmite.core.AnalyzeOptions;
import io.mailmite.core.MailmiteAnalyzer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Watches a folder for new *.ipa files. When a file appears AND finishes
 * being written (size stable for 2s), kicks off an analysis.
 */
public class WatcherDaemon {

    private static final Logger log = LoggerFactory.getLogger(WatcherDaemon.class);

    public static void main(String[] args) throws Exception {
        Path incoming = Path.of(env("INCOMING_DIR", "/var/mailmite/incoming"));
        Path reports  = Path.of(env("REPORT_DIR",   "/var/mailmite/reports"));
        Path ghidra   = Path.of(env("GHIDRA_HOME",  "/opt/ghidra"));
        Files.createDirectories(incoming);
        Files.createDirectories(reports);

        ExecutorService pool = Executors.newFixedThreadPool(
                Integer.parseInt(env("WORKER_THREADS", "2")));
        MailmiteAnalyzer analyzer = new MailmiteAnalyzer();

        try (WatchService ws = FileSystems.getDefault().newWatchService()) {
            incoming.register(ws, StandardWatchEventKinds.ENTRY_CREATE);
            log.info("watching {}", incoming);

            while (true) {
                WatchKey k = ws.take();
                for (WatchEvent<?> ev : k.pollEvents()) {
                    Path p = incoming.resolve((Path) ev.context());
                    if (!p.toString().toLowerCase().endsWith(".ipa")) continue;
                    pool.submit(() -> handle(analyzer, p, ghidra, reports));
                }
                k.reset();
            }
        }
    }

    private static void handle(MailmiteAnalyzer a, Path ipa, Path ghidra, Path reports) {
        try {
            waitStable(ipa);
            var r = a.analyze(AnalyzeOptions.builder()
                    .ipaPath(ipa).ghidraHome(ghidra)
                    .outputDir(reports.resolve(ipa.getFileName().toString().replace(".ipa", "")))
                    .build());
            log.info("done {} → {}", ipa.getFileName(), r.reportDir());
        } catch (Exception ex) {
            log.error("failed {}", ipa, ex);
        }
    }

    private static void waitStable(Path p) throws Exception {
        long prev = -1;
        for (int i = 0; i < 60; i++) {
            long cur = Files.size(p);
            if (cur == prev && cur > 0) return;
            prev = cur;
            Thread.sleep(2000);
        }
    }

    private static String env(String k, String def) {
        String v = System.getenv(k);
        return v == null ? def : v;
    }
}
