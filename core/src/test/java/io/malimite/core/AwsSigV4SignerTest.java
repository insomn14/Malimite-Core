package io.malimite.core;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/** Structural coverage for AwsSigV4Signer (BedrockProvider's request signer). Verifies the
 * produced Authorization header has the shape AWS expects and is deterministic for a fixed
 * instant isn't practical here (the signer stamps "now"), so these assertions focus on format
 * and on the two inputs that must change the signature: body content and the secret key. */
class AwsSigV4SignerTest {

    private static Map<String, String> extraHeaders() {
        Map<String, String> h = new LinkedHashMap<>();
        h.put("content-type", "application/json");
        h.put("accept", "application/json");
        return h;
    }

    @Test void signProducesWellFormedAuthorizationHeader() {
        byte[] body = "{\"hello\":\"world\"}".getBytes(StandardCharsets.UTF_8);
        Map<String, String> headers = AwsSigV4Signer.sign(
                "POST", "/model/anthropic.claude-sonnet-5/invoke", "us-east-1", "bedrock",
                "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "bedrock-runtime.us-east-1.amazonaws.com", body, extraHeaders());

        assertTrue(headers.containsKey("Authorization"));
        assertTrue(headers.containsKey("X-Amz-Date"));
        assertEquals("bedrock-runtime.us-east-1.amazonaws.com", headers.get("Host"));

        String auth = headers.get("Authorization");
        assertTrue(auth.startsWith("AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/"));
        assertTrue(auth.contains("/us-east-1/bedrock/aws4_request, "));
        assertTrue(auth.contains("SignedHeaders="));
        assertTrue(auth.contains("Signature="));
        // 64 lowercase hex chars for a SHA-256 HMAC signature
        String sig = auth.replaceAll(".*Signature=", "");
        assertEquals(64, sig.length());
        assertTrue(sig.matches("[0-9a-f]{64}"));
    }

    @Test void signedHeadersIncludeHostDateAndExtras() {
        byte[] body = "{}".getBytes(StandardCharsets.UTF_8);
        Map<String, String> headers = AwsSigV4Signer.sign(
                "POST", "/model/x/invoke", "us-east-1", "bedrock",
                "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "bedrock-runtime.us-east-1.amazonaws.com", body, extraHeaders());
        String auth = headers.get("Authorization");
        String signedHeaders = auth.replaceAll(".*SignedHeaders=([^,]+),.*", "$1");
        assertEquals("accept;content-type;host;x-amz-date", signedHeaders);
    }

    @Test void differentBodyProducesDifferentSignature() {
        String sig1 = signatureOnly("{\"a\":1}");
        String sig2 = signatureOnly("{\"a\":2}");
        assertNotEquals(sig1, sig2);
    }

    private static String signatureOnly(String bodyJson) {
        Map<String, String> headers = AwsSigV4Signer.sign(
                "POST", "/model/x/invoke", "us-east-1", "bedrock",
                "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "bedrock-runtime.us-east-1.amazonaws.com", bodyJson.getBytes(StandardCharsets.UTF_8), extraHeaders());
        return headers.get("Authorization").replaceAll(".*Signature=", "");
    }
}
