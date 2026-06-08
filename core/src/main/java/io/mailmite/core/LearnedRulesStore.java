package io.mailmite.core;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonArray;
import com.google.gson.JsonParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.file.*;
import java.util.*;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import static java.nio.file.StandardOpenOption.CREATE;
import static java.nio.file.StandardOpenOption.WRITE;

/**
 * Persistent JSON-backed store of LLM-discovered rules.
 * Survives between scans so that a vulnerability discovered via LLM on scan #N
 * is detected purely-statically (no LLM call) on scan #N+1.
 *
 * <p>File path: {@code $MAILMITE_LEARNED_RULES} or {@code $HOME/.mailmite/learned_rules.json}.
 *
 * <p>This class is thread-safe for single-process use only. Concurrent processes
 * writing simultaneously could clobber entries; the failure mode is "rule
 * not persisted", never corruption thanks to atomic-rename on save.
 */
public final class LearnedRulesStore {

    private static final Logger log = LoggerFactory.getLogger(LearnedRulesStore.class);

    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();

    private final Path file;
    private final Path lockFile;
    private final List<StoredRule> rules = new ArrayList<>();

    public LearnedRulesStore() {
        this(defaultPath());
    }

    public LearnedRulesStore(Path file) {
        this.file     = file;
        this.lockFile = file.resolveSibling(file.getFileName() + ".lock");
        load();
    }

    /** Resolves the configured storage path. */
    public static Path defaultPath() {
        String env = System.getenv("MAILMITE_LEARNED_RULES");
        if (env != null && !env.isBlank()) return Path.of(env);
        String home = System.getProperty("user.home", "/tmp");
        return Path.of(home, ".mailmite", "learned_rules.json");
    }

    // ── load / save ───────────────────────────────────────────────────────────

    private synchronized void load() {
        rules.clear();
        if (!Files.exists(file)) {
            log.info("LearnedRulesStore: no existing file at {}", file);
            return;
        }
        try {
            String json = Files.readString(file);
            JsonObject root = JsonParser.parseString(json).getAsJsonObject();
            JsonArray arr = root.has("rules") ? root.getAsJsonArray("rules") : new JsonArray();
            for (var el : arr) {
                try {
                    StoredRule r = GSON.fromJson(el, StoredRule.class);
                    if (r != null && r.id != null && r.regex != null) rules.add(r);
                } catch (Exception ex) {
                    log.warn("Skipping malformed learned rule: {}", ex.getMessage());
                }
            }
            log.info("LearnedRulesStore: loaded {} rule(s) from {}", rules.size(), file);
        } catch (IOException e) {
            log.warn("LearnedRulesStore: could not read {}: {}", file, e.getMessage());
        }
    }

    private synchronized void save() {
        try {
            Files.createDirectories(file.getParent());
            JsonObject root = new JsonObject();
            JsonArray arr = new JsonArray();
            for (StoredRule r : rules) arr.add(GSON.toJsonTree(r));
            root.add("rules", arr);
            Path tmp = file.resolveSibling(file.getFileName() + ".tmp");
            Files.writeString(tmp, GSON.toJson(root));
            Files.move(tmp, file, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            log.warn("LearnedRulesStore: could not save {}: {}", file, e.getMessage());
        }
    }

    // ── public API ────────────────────────────────────────────────────────────

    /**
     * Returns all stored rules as compiled {@link VulnerabilityRule} objects,
     * skipping any whose regex no longer compiles.
     */
    public synchronized List<VulnerabilityRule> asVulnerabilityRules() {
        List<VulnerabilityRule> out = new ArrayList<>();
        for (StoredRule r : rules) {
            try {
                Pattern p = Pattern.compile(r.regex);
                out.add(new VulnerabilityRule(
                        r.id, r.title, r.category, r.severity, r.cvssScore,
                        r.cwe, r.description, r.remediation, r.referenceUrl,
                        VulnerabilityRule.Target.valueOf(r.target),
                        p, r.pocTemplate));
            } catch (PatternSyntaxException ex) {
                log.warn("Stored rule {} regex no longer compiles, skipping: {}", r.id, ex.getMessage());
            } catch (IllegalArgumentException ex) {
                log.warn("Stored rule {} has invalid target: {}", r.id, ex.getMessage());
            }
        }
        return out;
    }

    /**
     * Adds a new rule; deduped by {@code (scope, normalizedRegex)} so that
     * regexes that differ only in whitespace or {@code [\s\S]}/{@code [\S\s]}
     * ordering are treated as identical.
     *
     * <p>This method holds an exclusive cross-process file lock during the
     * read-modify-write cycle, so concurrent Mailmite invocations against the
     * same {@code learned_rules.json} cannot lose each other's writes.
     *
     * @return the resolved rule ID (existing or newly minted), or {@code null}
     *         if the regex was invalid.
     */
    public synchronized String addRule(String scope, String title, String category,
                                        String severity, double cvssScore, String cwe,
                                        String description, String remediation,
                                        String target, String regex, String pocTemplate,
                                        String referenceUrl) {
        // Validate regex first — cheap rejection before taking the lock.
        try { Pattern.compile(regex); }
        catch (PatternSyntaxException ex) {
            log.warn("Rejected rule with invalid regex (scope={}): {}", scope, ex.getMessage());
            return null;
        }
        String normalized = normalizeRegex(regex);

        try {
            Files.createDirectories(lockFile.getParent());
        } catch (IOException ex) {
            log.warn("Could not create dir for lock file {}: {}", lockFile, ex.getMessage());
            // Fall through — addRule will still proceed in-memory.
        }

        try (FileChannel ch = FileChannel.open(lockFile, CREATE, WRITE);
             FileLock    lk = ch.lock()) {

            // Re-read current state inside the lock: another process may have
            // written rules since we constructed this store.
            reload();

            // Dedup on the normalized regex for the same scope
            for (StoredRule r : rules) {
                if (scope.equalsIgnoreCase(r.scope)
                        && normalized.equals(normalizeRegex(r.regex))) {
                    return r.id;
                }
            }

            String id = nextIdFor(scope);
            StoredRule r = new StoredRule();
            r.id           = id;
            r.scope        = scope;
            r.title        = title;
            r.category     = category;
            r.severity     = severity;
            r.cvssScore    = cvssScore;
            r.cwe          = cwe;
            r.description  = description;
            r.remediation  = remediation;
            r.referenceUrl = referenceUrl;
            r.target       = target;
            r.regex        = regex;
            r.pocTemplate  = pocTemplate;
            r.createdAt    = System.currentTimeMillis();
            rules.add(r);
            save();
            log.info("LearnedRulesStore: added rule {} ({})", id, title);
            return id;

        } catch (IOException ex) {
            log.warn("Could not acquire learned-rules lock {}: {} — falling back to in-memory append",
                    lockFile, ex.getMessage());
            // Best-effort fallback: in-memory dedup only, no cross-process safety
            for (StoredRule r : rules) {
                if (scope.equalsIgnoreCase(r.scope)
                        && normalized.equals(normalizeRegex(r.regex))) {
                    return r.id;
                }
            }
            String id = nextIdFor(scope);
            StoredRule r = new StoredRule();
            r.id = id; r.scope = scope; r.title = title; r.category = category;
            r.severity = severity; r.cvssScore = cvssScore; r.cwe = cwe;
            r.description = description; r.remediation = remediation;
            r.referenceUrl = referenceUrl; r.target = target; r.regex = regex;
            r.pocTemplate = pocTemplate; r.createdAt = System.currentTimeMillis();
            rules.add(r);
            save();
            return id;
        }
    }

    /** Re-read the JSON file from disk. Public so tests can simulate "another process wrote". */
    public synchronized void reload() {
        load();
    }

    // ── regex normalization ───────────────────────────────────────────────────

    /**
     * Returns a canonical form of a regex string for dedup-equality comparison.
     * Two regexes that differ only in cosmetic whitespace (outside character
     * classes) or in {@code [\s\S]} vs {@code [\S\s]} ordering will produce
     * the same normalized output.
     *
     * <p>Conservative: never aliases tokens that could change matching behaviour
     * (so {@code \d} is not collapsed to {@code [0-9]}, and lazy/greedy
     * quantifiers stay distinct).
     */
    static String normalizeRegex(String regex) {
        if (regex == null || regex.isEmpty()) return "";

        // Step 1: canonicalise common "match any char" forms.
        // [\S\s] is semantically identical to [\s\S]; both differ from "." only
        // when DOTALL is off, but for our dedup we treat all three as one token.
        String s = regex
                .replace("[\\S\\s]", "[\\s\\S]")
                .replace("[^]",       "[\\s\\S]");

        // Step 2: strip whitespace OUTSIDE character classes and OUTSIDE escapes.
        // Whitespace inside [...] can be significant (it really matches a space),
        // so we preserve it there. Escapes like \\  \(  \s are passed through.
        StringBuilder out = new StringBuilder(s.length());
        boolean inCharClass = false;
        boolean escape      = false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (escape) {
                out.append(c);
                escape = false;
                continue;
            }
            if (c == '\\') {
                out.append(c);
                escape = true;
                continue;
            }
            if (c == '[' && !inCharClass) {
                inCharClass = true;
                out.append(c);
                continue;
            }
            if (c == ']' && inCharClass) {
                inCharClass = false;
                out.append(c);
                continue;
            }
            if (!inCharClass && Character.isWhitespace(c)) continue;
            out.append(c);
        }
        return out.toString();
    }

    public synchronized int size() {
        return rules.size();
    }

    /** Compute next sequential ID like LLM-XSS-001, LLM-XSS-002 within a scope. */
    private String nextIdFor(String scope) {
        String prefix = "LLM-" + scope.toUpperCase() + "-";
        int max = 0;
        for (StoredRule r : rules) {
            if (r.id != null && r.id.startsWith(prefix)) {
                String suffix = r.id.substring(prefix.length());
                try { max = Math.max(max, Integer.parseInt(suffix)); } catch (NumberFormatException ignored) {}
            }
        }
        return prefix + String.format("%03d", max + 1);
    }

    // ── on-disk representation ────────────────────────────────────────────────

    public static class StoredRule {
        public String  id;
        public String  scope;
        public String  title;
        public String  category;
        public String  severity;
        public double  cvssScore;
        public String  cwe;
        public String  description;
        public String  remediation;
        public String  referenceUrl;
        public String  target;        // STRINGS|FUNCTION_NAMES|DECOMPILED|RESOURCES|ABSENCE
        public String  regex;
        public String  pocTemplate;
        public long    createdAt;
    }
}
