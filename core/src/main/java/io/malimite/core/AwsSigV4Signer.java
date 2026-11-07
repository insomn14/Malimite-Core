package io.malimite.core;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeMap;

/**
 * Minimal AWS Signature Version 4 request signer — JDK-only (javax.crypto/java.security), no
 * AWS SDK dependency, mirroring web/app/agent/aws_sigv4.py on the Python side.
 *
 * Scoped to exactly what {@link BedrockProvider} needs: signing one bedrock-runtime
 * InvokeModel POST request with a static access key id/secret pair (no session token /
 * STS support — the Config tab and LLM_PROVIDER=bedrock env vars only ever supply a static
 * pair, see LlmProviderFactory's javadoc).
 *
 * @see <a href="https://docs.aws.amazon.com/general/latest/gr/sigv4-signed-request-examples.html">
 *      AWS SigV4 signed request examples</a>
 */
final class AwsSigV4Signer {

    private static final DateTimeFormatter AMZ_DATE = DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'")
            .withZone(ZoneOffset.UTC);
    private static final DateTimeFormatter DATE_STAMP = DateTimeFormatter.ofPattern("yyyyMMdd")
            .withZone(ZoneOffset.UTC);

    private AwsSigV4Signer() {}

    /** Signed header map (including Authorization/Host/X-Amz-Date) for one request. */
    static Map<String, String> sign(String method, String urlPath, String region, String service,
                                     String accessKeyId, String secretAccessKey, String host,
                                     byte[] body, Map<String, String> extraHeaders) {
        Instant now = Instant.now();
        String amzDate = AMZ_DATE.format(now);
        String dateStamp = DATE_STAMP.format(now);

        String payloadHash = hex(sha256(body));

        // Headers are signed case-insensitively but transmitted lowercase in the canonical
        // request; TreeMap keeps them sorted the way AWS's algorithm requires.
        TreeMap<String, String> headersToSign = new TreeMap<>();
        headersToSign.put("host", host);
        headersToSign.put("x-amz-date", amzDate);
        for (Map.Entry<String, String> e : extraHeaders.entrySet()) {
            headersToSign.put(e.getKey().toLowerCase(java.util.Locale.ROOT), e.getValue());
        }

        StringBuilder canonicalHeaders = new StringBuilder();
        StringBuilder signedHeaderNames = new StringBuilder();
        for (Map.Entry<String, String> e : headersToSign.entrySet()) {
            canonicalHeaders.append(e.getKey()).append(':').append(e.getValue()).append('\n');
            if (signedHeaderNames.length() > 0) signedHeaderNames.append(';');
            signedHeaderNames.append(e.getKey());
        }
        String signedHeaders = signedHeaderNames.toString();

        String canonicalRequest = String.join("\n",
                method, urlPath, "", canonicalHeaders.toString(), signedHeaders, payloadHash);

        String credentialScope = dateStamp + "/" + region + "/" + service + "/aws4_request";
        String stringToSign = String.join("\n",
                "AWS4-HMAC-SHA256", amzDate, credentialScope, hex(sha256(canonicalRequest.getBytes(StandardCharsets.UTF_8))));

        byte[] signingKey = signingKey(secretAccessKey, dateStamp, region, service);
        String signature = hex(hmacSha256(signingKey, stringToSign));

        String authorization = "AWS4-HMAC-SHA256 Credential=" + accessKeyId + "/" + credentialScope
                + ", SignedHeaders=" + signedHeaders + ", Signature=" + signature;

        Map<String, String> out = new LinkedHashMap<>(extraHeaders);
        out.put("Host", host);
        out.put("X-Amz-Date", amzDate);
        out.put("Authorization", authorization);
        return out;
    }

    private static byte[] signingKey(String secretKey, String dateStamp, String region, String service) {
        byte[] kDate = hmacSha256(("AWS4" + secretKey).getBytes(StandardCharsets.UTF_8), dateStamp);
        byte[] kRegion = hmacSha256(kDate, region);
        byte[] kService = hmacSha256(kRegion, service);
        return hmacSha256(kService, "aws4_request");
    }

    private static byte[] hmacSha256(byte[] key, String data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalStateException("HMAC-SHA256 unavailable", e);
        }
    }

    private static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    private static String hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
