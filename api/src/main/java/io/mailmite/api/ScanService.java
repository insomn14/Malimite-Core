package io.mailmite.api;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mailmite.core.AnalysisReport;
import io.mailmite.core.SqliteStore;
import io.minio.BucketExistsArgs;
import io.minio.MakeBucketArgs;
import io.minio.MinioClient;
import io.minio.PutObjectArgs;
import redis.clients.jedis.JedisPooled;
import redis.clients.jedis.params.XAddParams;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import redis.clients.jedis.params.ScanParams;
import redis.clients.jedis.resps.ScanResult;

/**
 * Thin glue: stream uploaded IPA to MinIO, push job to Redis Stream
 * "mailmite:scans". The worker module consumes the stream.
 */
public class ScanService {

    private static final ObjectMapper JSON = new ObjectMapper();

    private static final String SCAN_INDEX = "mailmite:scan:index";

    private final JedisPooled redis;
    private final MinioClient minio;
    private final String bucket;
    private final Path reportDir;

    public ScanService(String redisUrl, String s3Endpoint,
                       String s3Access, String s3Secret, String bucket,
                       String reportDir) {
        this.redis  = new JedisPooled(redisUrl);
        this.minio  = MinioClient.builder().endpoint(s3Endpoint)
                        .credentials(s3Access, s3Secret).build();
        this.bucket = bucket;
        this.reportDir = Path.of(reportDir);
        ensureBucket();
    }

    private void ensureBucket() {
        try {
            boolean exists = minio.bucketExists(BucketExistsArgs.builder().bucket(bucket).build());
            if (!exists) minio.makeBucket(MakeBucketArgs.builder().bucket(bucket).build());
        } catch (Exception e) {
            throw new RuntimeException("minio init: " + e.getMessage(), e);
        }
    }

    public String enqueue(String filename, long size, InputStream content) {
        String scanId = UUID.randomUUID().toString();
        String objectKey = "incoming/" + scanId + ".ipa";
        try {
            minio.putObject(PutObjectArgs.builder()
                    .bucket(bucket).object(objectKey)
                    .stream(content, size, -1)
                    .contentType("application/octet-stream")
                    .build());
        } catch (Exception e) {
            throw new RuntimeException("upload failed: " + e.getMessage(), e);
        }

        String now = Instant.now().toString();
        redis.xadd("mailmite:scans", XAddParams.xAddParams(), Map.of(
                "scan_id", scanId,
                "object_key", objectKey,
                "filename", filename));
        redis.zadd(SCAN_INDEX, System.currentTimeMillis(), scanId);
        redis.hset("mailmite:meta:" + scanId, Map.of(
                "scan_id", scanId,
                "filename", filename,
                "created_at", now,
                "llm_enabled", "false",
                "llm_provider", "none",
                "llm_mode", "summarize",
                "llm_model", ""));
        redis.hset("mailmite:status:" + scanId, Map.of("state", "queued"));
        return scanId;
    }

    /** All scans, newest first — shape matches Python {@code GET /api/v1/scans}. */
    public List<ScanRecord.Meta> listScans() {
        Set<String> ids = new LinkedHashSet<>();
        List<String> indexed = redis.zrevrange(SCAN_INDEX, 0, -1);
        if (indexed != null) ids.addAll(indexed);
        ids.addAll(discoverStatusKeys());
        Map<String, String> filenames = filenameIndexFromStream();

        return ids.stream()
                .map(id -> buildMeta(id, filenames.get(id)))
                .sorted(Comparator.comparing(ScanRecord.Meta::created_at,
                        Comparator.nullsLast(Comparator.reverseOrder())))
                .collect(Collectors.toList());
    }

    public ScanRecord.Detail getDetail(String scanId) {
        Map<String, String> meta = redis.hgetAll("mailmite:meta:" + scanId);
        Map<String, String> st   = redis.hgetAll("mailmite:status:" + scanId);
        if (meta.isEmpty() && st.isEmpty()) return null;

        String filename = meta.getOrDefault("filename",
                filenameIndexFromStream().getOrDefault(scanId, scanId + ".ipa"));
        String state = st.getOrDefault("state", "unknown");
        Path dir = reportDir(scanId, st);

        String bundleId = null, bundleExe = null, dbPath = null, ipaPath = null;
        String teamId = null, profile = null, expiry = null;
        Boolean isSwift = null, isUniversal = null;
        List<String> archs = null;
        Integer classCount = null, fnCount = null, strCount = null;
        Integer epCount = null, llmCount = null;
        Map<String, Integer> vulnCounts = null;

        Path scanJson = dir.resolve("scan.json");
        if (Files.exists(scanJson)) {
            try {
                JsonNode n = JSON.readTree(scanJson.toFile());
                bundleId   = textOrNull(n, "bundleIdentifier");
                bundleExe  = textOrNull(n, "bundleExecutable");
                dbPath     = textOrNull(n, "dbPath");
                ipaPath    = textOrNull(n, "ipaPath");
                teamId     = textOrNull(n, "bundleTeamId");
                profile    = textOrNull(n, "provisioningProfile");
                expiry     = textOrNull(n, "provisioningExpiry");
                if (n.has("isSwift") && !n.get("isSwift").isNull()) isSwift = n.get("isSwift").asBoolean();
                if (n.has("isUniversal") && !n.get("isUniversal").isNull()) isUniversal = n.get("isUniversal").asBoolean();
                if (n.has("architectures") && n.get("architectures").isArray()) {
                    List<String> parsed = new ArrayList<>();
                    n.get("architectures").forEach(a -> parsed.add(a.asText()));
                    archs = parsed;
                }
            } catch (Exception ignored) {}
        }

        String resultJson = redis.get("mailmite:result:" + scanId);
        if (resultJson != null) {
            try {
                JsonNode n = JSON.readTree(resultJson);
                if (bundleId == null) bundleId = textOrNull(n, "bundleIdentifier");
                if (bundleExe == null) bundleExe = textOrNull(n, "bundleExecutable");
                classCount = n.path("classCount").asInt(0);
                fnCount    = n.path("functionCount").asInt(0);
                strCount   = n.path("stringCount").asInt(0);
                if (n.has("entryPoints")) epCount = n.get("entryPoints").size();
                if (n.has("llmFindings")) llmCount = n.get("llmFindings").size();
                if (n.has("vulnerabilities") && n.get("vulnerabilities").isArray()) {
                    vulnCounts = new HashMap<>();
                    for (JsonNode v : n.get("vulnerabilities")) {
                        String sev = v.path("severity").asText("INFO");
                        vulnCounts.merge(sev, 1, Integer::sum);
                    }
                }
            } catch (Exception ignored) {}
        }

        return new ScanRecord.Detail(
                scanId,
                filename,
                state,
                meta.get("created_at"),
                st.get("started_at"),
                st.get("finished_at"),
                parseIntOrNull(st.get("exit_code")),
                Boolean.parseBoolean(meta.getOrDefault("llm_enabled", "false")),
                meta.getOrDefault("llm_provider", "none"),
                meta.getOrDefault("llm_mode", "summarize"),
                meta.getOrDefault("llm_model", ""),
                bundleId, bundleExe, isSwift, isUniversal, archs,
                dbPath, ipaPath, teamId, profile, expiry,
                classCount, fnCount, strCount, epCount, llmCount, vulnCounts,
                Files.exists(dir.resolve("findings.sarif")),
                Files.exists(dir.resolve("report.html")),
                Files.exists(dir.resolve("analysis.log")),
                st.get("message"));
    }

    public Map<String, String> status(String scanId) {
        var m = redis.hgetAll("mailmite:status:" + scanId);
        return m.isEmpty() ? Map.of("state", "unknown") : m;
    }

    private Set<String> discoverStatusKeys() {
        Set<String> ids = new LinkedHashSet<>();
        String cursor = ScanParams.SCAN_POINTER_START;
        ScanParams params = new ScanParams().match("mailmite:status:*").count(200);
        do {
            ScanResult<String> batch = redis.scan(cursor, params);
            for (String key : batch.getResult()) {
                ids.add(key.substring("mailmite:status:".length()));
            }
            cursor = batch.getCursor();
        } while (!ScanParams.SCAN_POINTER_START.equals(cursor));
        return ids;
    }

    private Map<String, String> filenameIndexFromStream() {
        Map<String, String> map = new HashMap<>();
        try {
            var entries = redis.xrange("mailmite:scans", "-", "+");
            if (entries == null) return map;
            for (var e : entries) {
                Map<String, String> f = e.getFields();
                String id = f.get("scan_id");
                if (id != null) map.put(id, f.getOrDefault("filename", id + ".ipa"));
            }
        } catch (Exception ignored) {}
        return map;
    }

    private ScanRecord.Meta buildMeta(String scanId, String filenameFallback) {
        Map<String, String> meta = redis.hgetAll("mailmite:meta:" + scanId);
        Map<String, String> st   = redis.hgetAll("mailmite:status:" + scanId);
        if (filenameFallback == null) {
            filenameFallback = meta.getOrDefault("filename", scanId + ".ipa");
        }
        return new ScanRecord.Meta(
                scanId,
                meta.getOrDefault("filename", filenameFallback),
                st.getOrDefault("state", meta.isEmpty() && st.isEmpty() ? "unknown" : "queued"),
                meta.get("created_at"),
                st.get("started_at"),
                st.get("finished_at"),
                parseIntOrNull(st.get("exit_code")),
                Boolean.parseBoolean(meta.getOrDefault("llm_enabled", "false")),
                meta.getOrDefault("llm_provider", "none"),
                meta.getOrDefault("llm_mode", "summarize"),
                meta.getOrDefault("llm_model", ""));
    }

    private Path reportDir(String scanId, Map<String, String> status) {
        String fromStatus = status.get("report_dir");
        if (fromStatus != null && !fromStatus.isBlank()) return Path.of(fromStatus);
        return reportDir.resolve(scanId);
    }

    private static Integer parseIntOrNull(String v) {
        if (v == null || v.isBlank()) return null;
        try { return Integer.parseInt(v); } catch (NumberFormatException e) { return null; }
    }

    private static String textOrNull(JsonNode n, String field) {
        JsonNode v = n.path(field);
        if (v.isMissingNode() || v.isNull()) return null;
        String s = v.asText();
        return s.isBlank() ? null : s;
    }

    public String result(String scanId) {
        return redis.get("mailmite:result:" + scanId);  // full AnalysisReport JSON or null
    }

    /** Returns the lightweight ScanSummary portion of a completed scan, or null if not ready. */
    public AnalysisReport.ScanSummary summary(String scanId) {
        String json = redis.get("mailmite:result:" + scanId);
        if (json == null) return null;
        try {
            return JSON.treeToValue(JSON.readTree(json), AnalysisReport.ScanSummary.class);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Returns a paginated page of decompiled functions for a given class.
     * Reads directly from the SQLite file on the shared reports volume.
     */
    public AnalysisReport.FunctionPage functions(String scanId, String className, int page, int size) {
        String json = redis.get("mailmite:result:" + scanId);
        if (json == null) return null;
        try {
            JsonNode root       = JSON.readTree(json);
            String   dbPath     = root.path("dbPath").asText();
            String   execName   = root.path("bundleExecutable").asText();
            int      offset     = page * size;

            try (SqliteStore store = new SqliteStore(dbPath)) {
                int total = store.getFunctionCount(execName);
                List<Map<String, String>> rows = store.getFunctionsByClass(className, execName, offset, size);
                List<AnalysisReport.FunctionDetail> items = new ArrayList<>(rows.size());
                for (var row : rows) {
                    items.add(new AnalysisReport.FunctionDetail(
                            row.get("functionName"), className, row.get("decompiledCode")));
                }
                return new AnalysisReport.FunctionPage(className, page, size, total, items);
            }
        } catch (Exception e) {
            return null;
        }
    }
}
