package io.mailmite.api;

import io.javalin.Javalin;
import io.javalin.http.staticfiles.Location;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ApiServer {

    private static final Logger log = LoggerFactory.getLogger(ApiServer.class);

    public static void main(String[] args) {
        int port = Integer.parseInt(env("PORT", "8080"));
        long maxIpaMb = Long.parseLong(env("MAX_IPA_MB", "4096"));

        ScanService svc = new ScanService(
                env("REDIS_URL", "redis://localhost:6379"),
                env("MINIO_ENDPOINT", "http://localhost:9000"),
                env("MINIO_ACCESS", "minioadmin"),
                env("MINIO_SECRET", "minioadmin"),
                env("MINIO_BUCKET", "mailmite-ipa"));

        Javalin app = Javalin.create(cfg -> {
            cfg.http.maxRequestSize = maxIpaMb * 1024L * 1024L;
            cfg.staticFiles.add(staticFiles -> {
                staticFiles.hostedPath = "/";
                staticFiles.directory = "/web";
                staticFiles.location = Location.EXTERNAL;
            });
        });

        app.before("/api/*", ctx -> {
            String apiKey = ctx.header("X-Api-Key");
            String expected = System.getenv("MAILMITE_API_KEY");
            if (expected != null && !expected.equals(apiKey)) {
                ctx.status(401).result("unauthorized");
                ctx.skipRemainingHandlers();
            }
        });

        ScanController ctrl = new ScanController(svc);
        app.post("/api/v1/scans",                  ctrl::createScan);
        app.get ("/api/v1/scans/{id}",             ctrl::getScan);
        app.get ("/api/v1/scans/{id}/result",      ctrl::getResult);
        app.get ("/api/v1/scans/{id}/summary",     ctrl::getSummary);
        app.get ("/api/v1/scans/{id}/functions",   ctrl::getFunctions);

        app.get("/healthz", ctx -> ctx.result("ok"));

        app.start(port);
        log.info("Mailmite API listening on :{}", port);
    }

    private static String env(String k, String def) {
        String v = System.getenv(k);
        return v == null ? def : v;
    }
}
