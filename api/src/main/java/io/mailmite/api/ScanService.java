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
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Thin glue: stream uploaded IPA to MinIO, push job to Redis Stream
 * "mailmite:scans". The worker module consumes the stream.
 */
public class ScanService {

    private static final ObjectMapper JSON = new ObjectMapper();

    private final JedisPooled redis;
    private final MinioClient minio;
    private final String bucket;

    public ScanService(String redisUrl, String s3Endpoint,
                       String s3Access, String s3Secret, String bucket) {
        this.redis  = new JedisPooled(redisUrl);
        this.minio  = MinioClient.builder().endpoint(s3Endpoint)
                        .credentials(s3Access, s3Secret).build();
        this.bucket = bucket;
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

        redis.xadd("mailmite:scans", XAddParams.xAddParams(), Map.of(
                "scan_id", scanId,
                "object_key", objectKey,
                "filename", filename));
        redis.hset("mailmite:status:" + scanId, Map.of("state", "queued"));
        return scanId;
    }

    public Map<String, String> status(String scanId) {
        var m = redis.hgetAll("mailmite:status:" + scanId);
        return m.isEmpty() ? Map.of("state", "unknown") : m;
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
