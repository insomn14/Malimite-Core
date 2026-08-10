package io.mailmite.core;

import java.util.List;
import java.util.Map;

/**
 * One security-control inventory row produced by {@link AssessmentScanner}.
 * Distinct from {@link Vulnerability} — this answers "is the control implemented?"
 */
public record AssessmentResult(
        String controlId,
        String title,
        String category,
        AssessmentStatus status,
        String confidence,          // HIGH | MEDIUM | LOW
        List<String> evidence,
        Map<String, String> detail, // e.g. vendor, pinningStyle
        String platform             // IOS | ANDROID
) {
    public AssessmentResult {
        if (evidence == null) evidence = List.of();
        if (detail == null) detail = Map.of();
        if (confidence == null || confidence.isBlank()) confidence = "MEDIUM";
        if (status == null) status = AssessmentStatus.UNKNOWN;
    }

    public String evidenceJoined() {
        return String.join(" | ", evidence);
    }

    public String detailJoined() {
        if (detail.isEmpty()) return "";
        StringBuilder sb = new StringBuilder();
        detail.forEach((k, v) -> {
            if (!sb.isEmpty()) sb.append("; ");
            sb.append(k).append('=').append(v);
        });
        return sb.toString();
    }
}
