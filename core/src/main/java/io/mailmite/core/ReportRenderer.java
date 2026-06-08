package io.mailmite.core;

import java.nio.file.Path;

/**
 * Standalone CLI entry point: re-builds {@code report.html} and {@code findings.sarif}
 * for an existing scan directory by re-reading the current SQLite state.
 *
 * <p>Invoked by the Python service after every triage update so that
 * downloaded reports always reflect the latest reviewer decisions
 * (severity overrides, false-positive markings).
 *
 * <p>Usage:
 * <pre>java -cp mailmite-cli.jar io.mailmite.core.ReportRenderer &lt;scan-dir&gt;</pre>
 */
public final class ReportRenderer {

    private ReportRenderer() {}

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("Usage: ReportRenderer <scan-dir>");
            System.exit(2);
        }
        Path scanDir = Path.of(args[0]);

        AnalysisReport rep = ReportBuilder.buildFromDir(scanDir, 0L);
        Path html  = HtmlReporter.generate(rep, scanDir);
        Path sarif = SarifExporter.export(rep, scanDir);

        System.out.println("html="  + html);
        System.out.println("sarif=" + sarif);
    }
}
