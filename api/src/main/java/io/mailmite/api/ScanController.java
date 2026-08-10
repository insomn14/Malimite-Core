package io.mailmite.api;

import io.javalin.http.Context;
import io.javalin.http.UploadedFile;
import io.mailmite.core.AnalysisReport;

import java.util.Map;

public class ScanController {

    private final ScanService svc;
    public ScanController(ScanService svc) { this.svc = svc; }

    /** GET /api/v1/scans — list all scans (newest first). */
    public void listScans(Context ctx) {
        ctx.json(svc.listScans());
    }

    /** POST /api/v1/scans — multipart 'file' (IPA or APK). */
    public void createScan(Context ctx) {
        UploadedFile up = ctx.uploadedFile("file");
        if (up == null) { ctx.status(400).json(Map.of("error", "missing 'file' field")); return; }
        String name = up.filename().toLowerCase();
        if (!name.endsWith(".ipa") && !name.endsWith(".apk")) {
            ctx.status(415).json(Map.of("error", "only .ipa or .apk accepted"));
            return;
        }
        String scanId = svc.enqueue(up.filename(), up.size(), up.content());
        ctx.status(202).json(Map.of(
                "scan_id", scanId,
                "status", "queued",
                "result_url", "/api/v1/scans/" + scanId + "/result"));
    }

    /** GET /api/v1/scans/{id} — scan detail (SPA-compatible). */
    public void getScan(Context ctx) {
        String id = ctx.pathParam("id");
        ScanRecord.Detail detail = svc.getDetail(id);
        if (detail == null) { ctx.status(404).json(Map.of("error", "scan not found")); return; }
        ctx.json(detail);
    }

    /** GET /api/v1/scans/{id}/result — full AnalysisReport JSON. */
    public void getResult(Context ctx) {
        String id = ctx.pathParam("id");
        var res = svc.result(id);
        if (res == null) { ctx.status(404).result("not ready"); return; }
        ctx.json(res);
    }

    /** GET /api/v1/scans/{id}/summary — lightweight counts + metadata. */
    public void getSummary(Context ctx) {
        String id = ctx.pathParam("id");
        AnalysisReport.ScanSummary summary = svc.summary(id);
        if (summary == null) { ctx.status(404).result("not ready"); return; }
        ctx.json(summary);
    }

    /**
     * GET /api/v1/scans/{id}/functions?class=ClassName&page=0&size=50
     * Returns decompiled functions for one class, paginated.
     */
    public void getFunctions(Context ctx) {
        String id        = ctx.pathParam("id");
        String className = ctx.queryParam("class");
        int    page      = intParam(ctx, "page", 0);
        int    size      = Math.min(intParam(ctx, "size", 50), 200);

        if (className == null || className.isBlank()) {
            ctx.status(400).json(Map.of("error", "query param 'class' is required"));
            return;
        }
        AnalysisReport.FunctionPage fp = svc.functions(id, className, page, size);
        if (fp == null) { ctx.status(404).result("not ready or scan not found"); return; }
        ctx.json(fp);
    }

    private static int intParam(Context ctx, String name, int def) {
        String v = ctx.queryParam(name);
        if (v == null) return def;
        try { return Integer.parseInt(v); } catch (NumberFormatException e) { return def; }
    }
}
