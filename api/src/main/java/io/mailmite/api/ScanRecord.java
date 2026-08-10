package io.mailmite.api;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.List;
import java.util.Map;

/**
 * JSON shapes expected by the web SPA (matches Python {@code ScanMeta} / {@code ScanDetail}).
 */
public final class ScanRecord {

    private ScanRecord() {}

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Meta(
            String scan_id,
            String filename,
            String state,
            String created_at,
            String started_at,
            String finished_at,
            Integer exit_code,
            boolean llm_enabled,
            String llm_provider,
            String llm_mode,
            String llm_model
    ) {}

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Detail(
            String scan_id,
            String filename,
            String state,
            String created_at,
            String started_at,
            String finished_at,
            Integer exit_code,
            boolean llm_enabled,
            String llm_provider,
            String llm_mode,
            String llm_model,
            String bundle_id,
            String bundle_executable,
            String platform,
            Boolean is_swift,
            Boolean is_universal,
            List<String> architectures,
            String db_path,
            String ipa_path,
            String team_id,
            String provisioning_profile,
            String provisioning_expiry,
            Integer min_sdk,
            Integer target_sdk,
            Integer class_count,
            Integer function_count,
            Integer string_count,
            Integer entry_point_count,
            Integer llm_finding_count,
            Map<String, Integer> vulnerability_counts,
            boolean has_sarif,
            boolean has_html,
            boolean has_log,
            String message
    ) {}
}
