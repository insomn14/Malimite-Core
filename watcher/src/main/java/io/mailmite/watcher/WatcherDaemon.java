package io.mailmite.watcher;

import io.mailmite.core.AnalyzeOptions;
import io.mailmite.core.MailmiteAnalyzer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Watches a folder for new *.ipa / *.apk files. When a file appears AND finishes
 * being written (size stable for 2s), kicks off an analysis.
 */
public class WatcherDaemon {

    private static final Logger log = LoggerFactory.getLogger(WatcherDaemon.class);

    public static void main(String[] args) throws Exception {
        Path incoming = Path.of(env("INCOMING_DIR", "/var/mailmite/incoming"));
        Path reports  = Path.of(env("REPORT_DIR",   "/var/mailmite/reports"));
        Path ghidra   = Path.of(env("GHIDRA_HOME",  "/opt/ghidra"));
        String jadxEnv = System.getenv("JADX_HOME");
        Path jadx     = (jadxEnv == null || jadxEnv.isBlank()) ? null : Path.of(jadxEnv);
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
                    String lower = p.toString().toLowerCase();
                    if (!lower.endsWith(".ipa") && !lower.endsWith(".apk")) continue;
                    pool.submit(() -> handle(analyzer, p, ghidra, jadx, reports));
                }
                k.reset();
            }
        }
    }

    private static void handle(MailmiteAnalyzer a, Path pkg, Path ghidra, Path jadx, Path reports) {
        try {
            waitStable(pkg);
            String stem = pkg.getFileName().toString()
                    .replaceAll("(?i)\\.(ipa|apk)$", "");
            var r = a.analyze(AnalyzeOptions.builder()
                    .packagePath(pkg)
                    .ghidraHome(ghidra)
                    .jadxHome(jadx)
                    .outputDir(reports.resolve(stem))
                    .build());
            log.info("done {} → {}", pkg.getFileName(), r.reportDir());
        } catch (Exception ex) {
            log.error("failed {}", pkg, ex);
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
