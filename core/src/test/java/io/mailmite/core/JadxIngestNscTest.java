package io.mailmite.core;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertTrue;

class JadxIngestNscTest {

    @TempDir Path tmp;

    @Test
    void nscSnippetsPopulateResourceStrings() throws Exception {
        Path db = tmp.resolve("nsc.sqlite");
        try (SqliteStore store = new SqliteStore(db.toString())) {
            String xml = """
                    <network-security-config>
                      <base-config cleartextTrafficPermitted="true">
                        <trust-anchors>
                          <certificates src="user"/>
                        </trust-anchors>
                      </base-config>
                      <domain-config>
                        <pin-set expiration="2020-01-01">
                          <pin digest="SHA-256">abc=</pin>
                        </pin-set>
                      </domain-config>
                    </network-security-config>
                    """;
            JadxIngest.ingestNscSnippets(store, xml);
            List<Map<String, String>> rows = store.getResourceStrings();
            String joined = rows.stream().map(r -> r.get("value")).reduce("", (a, b) -> a + "\n" + b);
            assertTrue(joined.contains("cleartextTrafficPermitted=true"));
            assertTrue(joined.contains("trust-anchors-user") || joined.contains("src=\"user\""));
            assertTrue(joined.contains("pin-set-present") || joined.contains("pin-expiration"));
        }
    }
}
