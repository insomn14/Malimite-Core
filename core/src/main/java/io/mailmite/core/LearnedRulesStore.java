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
 * Persistent JSON-backed store of LLM-discovered rules, separated by platform.
 *
 * <p>Paths:
 * <ul>
 *   <li>iOS: {@code $MAILMITE_LEARNED_RULES_IOS} or {@code $MAILMITE_LEARNED_RULES}
 *       or {@code ~/.mailmite/learned_rules.json}</li>
 *   <li>Android: {@code $MAILMITE_LEARNED_RULES_ANDROID}
 *       or {@code ~/.mailmite/learned_rules_android.json}</li>
 * </ul>
 *
 * <p>On load of the iOS file, rules missing {@code platform} are migrated to {@code IOS}.
 */
public final class LearnedRulesStore {

    private static final Logger log = LoggerFactory.getLogger(LearnedRulesStore.class);

    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();

    private final Path file;
    private final Path lockFile;
    private final PackagePlatform storePlatform;
    private final List<StoredRule> rules = new ArrayList<>();

    public LearnedRulesStore() {
        this(PackagePlatform.IOS);
    }

    public LearnedRulesStore(PackagePlatform platform) {
        this(defaultPath(platform), platform);
    }

    public LearnedRulesStore(Path file) {
        this(file, PackagePlatform.IOS);
    }

    public LearnedRulesStore(Path file, PackagePlatform platform) {
        this.file = file;
        this.lockFile = file.resolveSibling(file.getFileName() + ".lock");
        this.storePlatform = platform == null ? PackagePlatform.IOS : platform;
        load();
    }

    public static LearnedRulesStore forPlatform(PackagePlatform platform) {
        return new LearnedRulesStore(platform == null ? PackagePlatform.IOS : platform);
    }

    /** Resolves iOS path (legacy default). */
    public static Path defaultPath() {
        return defaultPath(PackagePlatform.IOS);
    }

    public static Path defaultPath(PackagePlatform platform) {
        if (platform == PackagePlatform.ANDROID) {
            String env = System.getenv("MAILMITE_LEARNED_RULES_ANDROID");
            if (env != null && !env.isBlank()) return Path.of(env);
            String home = System.getProperty("user.home", "/tmp");
            return Path.of(home, ".mailmite", "learned_rules_android.json");
        }
        String iosEnv = System.getenv("MAILMITE_LEARNED_RULES_IOS");
        if (iosEnv != null && !iosEnv.isBlank()) return Path.of(iosEnv);
        String legacy = System.getenv("MAILMITE_LEARNED_RULES");
        if (legacy != null && !legacy.isBlank()) return Path.of(legacy);
        String home = System.getProperty("user.home", "/tmp");
        return Path.of(home, ".mailmite", "learned_rules.json");
    }

    public PackagePlatform storePlatform() {
        return storePlatform;
    }

    public Path file() {
        return file;
    }

    private synchronized void load() {
        rules.clear();
        if (!Files.exists(file)) {
            log.info("LearnedRulesStore: no existing file at {}", file);
            return;
        }
        boolean needsMigration = false;
        try {
            String json = Files.readString(file);
            JsonObject root = JsonParser.parseString(json).getAsJsonObject();
            JsonArray arr = root.has("rules") ? root.getAsJsonArray("rules") : new JsonArray();
            for (var el : arr) {
                try {
                    StoredRule r = GSON.fromJson(el, StoredRule.class);
                    if (r == null || r.id == null || r.regex == null) continue;
                    if (r.platform == null || r.platform.isBlank()) {
                        r.platform = storePlatform.name();
                        needsMigration = true;
                    }
                    rules.add(r);
                } catch (Exception ex) {
                    log.warn("Skipping malformed learned rule: {}", ex.getMessage());
                }
            }
            log.info("LearnedRulesStore: loaded {} rule(s) from {} (platform={})",
                    rules.size(), file, storePlatform);
            if (needsMigration && storePlatform == PackagePlatform.IOS) {
                save();
                log.info("LearnedRulesStore: migrated {} rule(s) to platform=IOS in {}",
                        rules.size(), file);
            }
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

    public synchronized List<VulnerabilityRule> asVulnerabilityRules() {
        List<VulnerabilityRule> out = new ArrayList<>();
        for (StoredRule r : rules) {
            if (!isUsableDetectionRegex(r.regex)) {
                log.warn("Stored rule {} has unusable/placeholder regex, skipping: {}",
                        r.id, abbreviate(r.regex, 60));
                continue;
            }
            try {
                Pattern p = Pattern.compile(r.regex);
                VulnerabilityRule.Platform plat = parsePlatform(r.platform);
                out.add(new VulnerabilityRule(
                        r.id, r.title, r.category, r.severity, r.cvssScore,
                        r.cwe, r.description, r.remediation, r.referenceUrl,
                        VulnerabilityRule.Target.valueOf(r.target),
                        p, r.pocTemplate, plat));
            } catch (PatternSyntaxException ex) {
                log.warn("Stored rule {} regex no longer compiles, skipping: {}", r.id, ex.getMessage());
            } catch (IllegalArgumentException ex) {
                log.warn("Stored rule {} has invalid target: {}", r.id, ex.getMessage());
            }
        }
        return out;
    }

    /**
     * Rejects blank, ellipsis placeholders ({@code ...}), and other regexes that would
     * match almost any decompiled body (e.g. three dots → any three characters).
     */
    public static boolean isUsableDetectionRegex(String regex) {
        if (regex == null) return false;
        String t = regex.trim();
        if (t.isEmpty() || t.length() < 6) return false;
        if (isPlaceholderText(t)) return false;
        // Only wildcards / dots / trivial quantifiers — too greedy for learning.
        if (t.matches("^[.\\s*+?|()\\[\\]{}^$\\\\sSdDwW]+$")) return false;
        return true;
    }

    /** True for LLM filler like {@code ...}, {@code …}, or {@code 1. ...\n2. ...}. */
    public static boolean isPlaceholderText(String s) {
        if (s == null) return true;
        String t = s.trim();
        if (t.isEmpty()) return true;
        if (t.matches("^[.\\u2026\\s]+$")) return true;
        if (t.equalsIgnoreCase("todo") || t.equalsIgnoreCase("tbd")
                || t.equalsIgnoreCase("n/a") || t.equalsIgnoreCase("none")
                || t.equalsIgnoreCase("placeholder")) {
            return true;
        }
        // Numbered stub lists: "1. ...\n2. ...\n3. ..."
        return t.matches("(?s)(\\d+\\.\\s*[.\\u2026]+\\s*)+");
    }

    private static String abbreviate(String s, int max) {
        if (s == null) return "";
        return s.length() <= max ? s : s.substring(0, max) + "…";
    }

    private static VulnerabilityRule.Platform parsePlatform(String p) {
        if (p == null || p.isBlank()) return VulnerabilityRule.Platform.IOS;
        try {
            return VulnerabilityRule.Platform.valueOf(p.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            return VulnerabilityRule.Platform.IOS;
        }
    }

    public synchronized String addRule(String scope, String title, String category,
                                        String severity, double cvssScore, String cwe,
                                        String description, String remediation,
                                        String target, String regex, String pocTemplate,
                                        String referenceUrl) {
        return addRule(scope, title, category, severity, cvssScore, cwe,
                description, remediation, target, regex, pocTemplate, referenceUrl,
                storePlatform.name());
    }

    public synchronized String addRule(String scope, String title, String category,
                                        String severity, double cvssScore, String cwe,
                                        String description, String remediation,
                                        String target, String regex, String pocTemplate,
                                        String referenceUrl, String platform) {
        if (!isUsableDetectionRegex(regex)) {
            log.warn("Rejected rule with unusable/placeholder regex (scope={}): {}",
                    scope, abbreviate(regex, 80));
            return null;
        }
        try { Pattern.compile(regex); }
        catch (PatternSyntaxException ex) {
            log.warn("Rejected rule with invalid regex (scope={}): {}", scope, ex.getMessage());
            return null;
        }
        String normalized = normalizeRegex(regex);
        String plat = (platform == null || platform.isBlank()) ? storePlatform.name() : platform;

        try {
            Files.createDirectories(lockFile.getParent());
        } catch (IOException ex) {
            log.warn("Could not create dir for lock file {}: {}", lockFile, ex.getMessage());
        }

        try (FileChannel ch = FileChannel.open(lockFile, CREATE, WRITE);
             FileLock lk = ch.lock()) {

            reload();

            for (StoredRule r : rules) {
                if (scope.equalsIgnoreCase(r.scope)
                        && normalized.equals(normalizeRegex(r.regex))) {
                    return r.id;
                }
            }

            String id = nextIdFor(scope);
            StoredRule r = newStored(id, scope, title, category, severity, cvssScore, cwe,
                    description, remediation, referenceUrl, target, regex, pocTemplate, plat);
            rules.add(r);
            save();
            log.info("LearnedRulesStore: added rule {} ({}) platform={}", id, title, plat);
            return id;

        } catch (IOException ex) {
            log.warn("Could not acquire learned-rules lock {}: {} — falling back to in-memory append",
                    lockFile, ex.getMessage());
            for (StoredRule r : rules) {
                if (scope.equalsIgnoreCase(r.scope)
                        && normalized.equals(normalizeRegex(r.regex))) {
                    return r.id;
                }
            }
            String id = nextIdFor(scope);
            rules.add(newStored(id, scope, title, category, severity, cvssScore, cwe,
                    description, remediation, referenceUrl, target, regex, pocTemplate, plat));
            save();
            return id;
        }
    }

    private static StoredRule newStored(String id, String scope, String title, String category,
                                        String severity, double cvssScore, String cwe,
                                        String description, String remediation, String referenceUrl,
                                        String target, String regex, String pocTemplate, String platform) {
        StoredRule r = new StoredRule();
        r.id = id; r.scope = scope; r.title = title; r.category = category;
        r.severity = severity; r.cvssScore = cvssScore; r.cwe = cwe;
        r.description = description; r.remediation = remediation;
        r.referenceUrl = referenceUrl; r.target = target; r.regex = regex;
        r.pocTemplate = pocTemplate; r.createdAt = System.currentTimeMillis();
        r.platform = platform;
        return r;
    }

    public synchronized void reload() {
        load();
    }

    static String normalizeRegex(String regex) {
        if (regex == null || regex.isEmpty()) return "";
        String s = regex
                .replace("[\\S\\s]", "[\\s\\S]")
                .replace("[^]", "[\\s\\S]");
        StringBuilder out = new StringBuilder(s.length());
        boolean inCharClass = false;
        boolean escape = false;
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
        public String  target;
        public String  regex;
        public String  pocTemplate;
        public long    createdAt;
        /** IOS or ANDROID — missing values migrate to IOS on iOS store load. */
        public String  platform;
    }
}
