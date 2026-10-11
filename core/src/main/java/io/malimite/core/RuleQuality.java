package io.malimite.core;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Quality gates for LLM-learned detection regexes.
 *
 * <p>A learned rule used to be accepted as soon as its regex matched the one function it was learned from. That says
 * nothing about whether it matches <em>everything else</em>: {@code \*\w+ = \*\w+ ^ \w+;} "detects XOR flag encryption"
 * but also matches every opcode handler of a bytecode VM, and {@code SoftwareBreakpoint\s*\(} is just how Ghidra prints a
 * compiler trap. Cheap gates keep such rules out:
 * <ol>
 *   <li><b>Semantic anchor</b> ({@link #hasSemanticAnchor}): every top-level alternative of the regex must contain a
 *       literal that names something specific (an API, a class, a constant), not just decompiler vocabulary
 *       ({@code param_1}, {@code uVar3}, {@code ulong}, ...).</li>
 *   <li><b>Word boundaries</b> ({@link #isBounded}): a short generic word such as {@code exec} or {@code Runtime} must be
 *       delimited ({@code Runtime\.getRuntime\(\)\.exec\(}); {@code (?:Runtime|exec)} also matches
 *       {@code execute()}, {@code Executors} and {@code RuntimeIntegritySdk}.</li>
 *   <li><b>Specificity</b> ({@link #isTooBroad}): the regex must not match more than a small share of the other
 *       functions of the same app.</li>
 * </ol>
 * {@link #passes} combines the first two; they are static, so they also protect rules that were stored before the
 * gates existed.
 */
public final class RuleQuality {

    private RuleQuality() {}

    /** A pattern may match at most this share of the other functions, but always at least {@link #MIN_ALLOWED_HITS}. */
    public static final double MAX_MATCH_RATE = 0.03;
    public static final int MIN_ALLOWED_HITS = 3;

    /** Words that carry no meaning for detection: language keywords, C types, ubiquitous runtime calls. */
    private static final Set<String> GENERIC = Set.of(
            // C / Java keywords and basic types
            "char", "uchar", "short", "ushort", "int", "uint", "long", "ulong", "byte", "void", "bool", "boolean",
            "float", "double", "return", "while", "for", "break", "continue", "sizeof", "null", "true", "false",
            "struct", "class", "static", "final", "public", "private", "protected", "this", "super", "else", "case",
            "switch", "default", "new", "try", "catch", "throw", "throws", "var", "val", "get", "set", "the", "and",
            "not", "string", "object", "length", "size", "value", "data", "name", "type", "index", "count", "result",
            "buffer", "code", "undefined", "unsigned", "signed", "const", "extern", "typedef", "enum", "union",
            // Ghidra renderings of CPU instructions / analysis gaps, not application behaviour
            "softwarebreakpoint", "halt_baddata", "halt_unimplemented", "halt_overflow", "warning", "concat",
            "sext", "zext", "cast", "pcodeop", "trap", "syscall",
            // present in practically every Objective-C / Swift function
            "objc_msgsend", "objc_msgsendsuper2", "objc_retain", "objc_release", "objc_autorelease",
            "objc_retainautoreleasedreturnvalue", "objc_autoreleasereturnvalue", "objc_storestrong",
            "swift_retain", "swift_release", "swift_bridgeobjectretain", "swift_bridgeobjectrelease",
            "swift_allocobject", "swift_unknownobjectrelease", "swift_getbridgedobjc");

    /** Names Ghidra invents: param_1, local_28, uVar3, pcVar7, auStack_78, DAT_..., FUN_..., PTR_..., LAB_... */
    private static final Pattern DECOMPILER_NAME = Pattern.compile(
            "(?i)^(?:param|local|[a-z]{0,3}var\\d*|austack|lab|dat|fun|ptr|unaff|extraout|undefined\\d*|in_?|switchd)(?:_.*|\\d.*)?$");

    private static final Pattern IDENT = Pattern.compile("[A-Za-z_][A-Za-z0-9_]{2,}");

    /** Static quality gate used when learning and when loading stored rules. */
    public static boolean passes(String regex) {
        return hasSemanticAnchor(regex) && isBounded(regex);
    }

    /** Why {@link #passes} rejects {@code regex}, or null when it passes (for logs). */
    public static String rejection(String regex) {
        if (!hasSemanticAnchor(regex)) return "no semantic anchor: only decompiler vocabulary, so it matches generic code";
        if (!isBounded(regex)) return "only short unbounded words (e.g. exec/Runtime) that also match longer identifiers";
        return null;
    }

    /**
     * True when every top-level alternative has a <em>strong</em> literal (long, camelCase or underscored: unlikely to
     * occur inside another identifier) or a literal with a delimiter next to it.
     */
    public static boolean isBounded(String regex) {
        if (regex == null) return false;
        for (String branch : topLevelAlternatives(regex)) {
            if (!branchIsBounded(branch)) return false;
        }
        return true;
    }

    private static boolean branchIsBounded(String branch) {
        String masked = mask(branch);
        Matcher m = Pattern.compile("[A-Za-z_][A-Za-z0-9_]{2,}").matcher(masked);
        while (m.find()) {
            String tok = m.group();
            if (GENERIC.contains(tok.toLowerCase(Locale.ROOT)) || DECOMPILER_NAME.matcher(tok).matches()) continue;
            if (isStrong(tok)) return true;
            char before = m.start() == 0 ? STRUCT : masked.charAt(m.start() - 1);
            char after = m.end() >= masked.length() ? STRUCT : masked.charAt(m.end());
            if (before == DELIM || after == DELIM) return true;
        }
        return false;
    }

    /** Long and distinctive: camelCase, underscored or digit-bearing names rarely appear inside other identifiers. */
    private static boolean isStrong(String tok) {
        if (tok.length() < 8) return false;
        return tok.indexOf('_') >= 0 || tok.matches(".*[a-z][A-Z].*") || tok.matches(".*[0-9].*");
    }

    private static final char DELIM = '\u0001';   // something that ends an identifier: \s \b \. \( a quote, a space...
    private static final char WORDC = '\u0002';   // something that may continue one: \w \d [A-Za-z]
    private static final char STRUCT = '\u0003';  // regex structure ( ) | ? * + ^ $ -- guarantees nothing

    /** Length of the group prefix at {@code r[i]=='('} followed by '?': (?: (?= (?! (?<= (?<! (?<name> (?i) (?i: ... */
    private static int groupPrefixLength(String r, int i) {
        int j = i + 2;
        if (j < r.length()) {
            char c = r.charAt(j);
            if (c == ':' || c == '=' || c == '!' || c == '>') return j + 1 - i;
            if (c == '<') {
                if (j + 1 < r.length() && (r.charAt(j + 1) == '=' || r.charAt(j + 1) == '!')) return j + 2 - i;
                int k = r.indexOf('>', j);
                return k < 0 ? j + 1 - i : k + 1 - i;
            }
            int k = j;
            while (k < r.length() && (Character.isLetter(r.charAt(k)) || r.charAt(k) == '-')) k++;
            if (k < r.length() && (r.charAt(k) == ')' || r.charAt(k) == ':')) return k + 1 - i;
        }
        return 2;
    }

    /** Replaces regex syntax with the three marker characters so literals can look at their neighbours. */
    private static String mask(String r) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < r.length(); i++) {
            char c = r.charAt(i);
            if (c == '\\' && i + 1 < r.length()) {
                char n = r.charAt(++i);
                out.append(n == 'w' || n == 'd' || n == 'W' || n == 'D' ? WORDC : DELIM);
                continue;
            }
            if (c == '[') {
                int j = i + 1;
                boolean wordish = false;
                while (j < r.length() && r.charAt(j) != ']') {
                    if (r.charAt(j) == '\\') {
                        if (j + 1 < r.length() && "wd".indexOf(r.charAt(j + 1)) >= 0) wordish = true;
                        j++;
                    } else if (Character.isLetterOrDigit(r.charAt(j)) && j + 1 < r.length() && r.charAt(j + 1) == '-') {
                        wordish = true;
                    }
                    j++;
                }
                out.append(wordish ? WORDC : DELIM);
                i = j;
                continue;
            }
            if (c == '{') {                       // quantifier {m,n}: not a literal, no information
                int j = r.indexOf('}', i);
                if (j > 0 && r.substring(i + 1, j).matches("\\d+(,\\d*)?")) { i = j; continue; }
            }
            if (c == '(' && i + 1 < r.length() && r.charAt(i + 1) == '?') {
                out.append(STRUCT);
                i += groupPrefixLength(r, i) - 1;
                continue;
            }
            if ("()|?*+^$".indexOf(c) >= 0) { out.append(STRUCT); continue; }
            if (Character.isLetterOrDigit(c) || c == '_') { out.append(c); continue; }
            out.append(DELIM);                    // '.', '(' as literal handled above via escapes; space, quote, '<', ...
        }
        return out.toString();
    }

    /** True when every top-level alternative of {@code regex} contains at least one meaningful literal. */
    public static boolean hasSemanticAnchor(String regex) {
        if (regex == null || regex.isBlank()) return false;
        for (String branch : topLevelAlternatives(regex)) {
            if (meaningfulLiterals(branch).isEmpty()) return false;
        }
        return true;
    }

    /** Literals of a regex fragment that are neither escapes, character classes, groups syntax nor generic words. */
    public static List<String> meaningfulLiterals(String fragment) {
        String s = fragment
                .replaceAll("\\\\[a-zA-Z0-9]", " ")                 // \w \s \d \b \1
                .replaceAll("\\\\.", " ")                          // \( \. \* \[
                .replaceAll("\\[(?:\\\\.|[^\\]\\\\])*\\]", " ")    // [...]
                .replaceAll("\\(\\?[<!=:a-zA-Z-]*", " ")           // (?: (?i) (?! (?<=
                .replaceAll("\\{\\d+(?:,\\d*)?\\}", " ");          // {3} {1,5}
        List<String> out = new ArrayList<>();
        Matcher m = IDENT.matcher(s);
        while (m.find()) {
            String tok = m.group();
            if (GENERIC.contains(tok.toLowerCase(Locale.ROOT))) continue;
            if (DECOMPILER_NAME.matcher(tok).matches()) continue;
            out.add(tok);
        }
        return out;
    }

    /** Splits on '|' outside groups, character classes and escapes. */
    static List<String> topLevelAlternatives(String regex) {
        List<String> parts = new ArrayList<>();
        int depth = 0;
        boolean inClass = false;
        StringBuilder cur = new StringBuilder();
        for (int i = 0; i < regex.length(); i++) {
            char c = regex.charAt(i);
            if (c == '\\' && i + 1 < regex.length()) {
                cur.append(c).append(regex.charAt(++i));
                continue;
            }
            if (inClass) {
                if (c == ']') inClass = false;
            } else if (c == '[') {
                inClass = true;
            } else if (c == '(') {
                depth++;
            } else if (c == ')') {
                depth = Math.max(0, depth - 1);
            } else if (c == '|' && depth == 0) {
                parts.add(cur.toString());
                cur.setLength(0);
                continue;
            }
            cur.append(c);
        }
        parts.add(cur.toString());
        return parts;
    }

    /** Number of corpus bodies the pattern may match before it is considered too broad. */
    public static int allowedHits(int corpusSize) {
        return Math.max(MIN_ALLOWED_HITS, (int) Math.ceil(MAX_MATCH_RATE * corpusSize));
    }

    /**
     * True when {@code p} matches more of the other functions than {@link #allowedHits} permits.
     *
     * @param own    the body the rule was learned from (that one occurrence is skipped; identical copies count)
     * @param corpus decompiled bodies of the same app
     */
    public static boolean isTooBroad(Pattern p, String own, Collection<String> corpus) {
        int limit = allowedHits(corpus.size());
        int hits = 0;
        boolean ownSkipped = false;
        for (String body : corpus) {
            if (body == null) continue;
            if (!ownSkipped && body.equals(own)) {   // the function the rule came from: skip it once, not its copies
                ownSkipped = true;
                continue;
            }
            if (p.matcher(body).find() && ++hits > limit) return true;
        }
        return false;
    }

    // ── learned rules are hypotheses: cap how loudly they can speak ──────────────────────────────────────────────

    private static final List<String> SEVERITIES = List.of("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO");

    /** A learned rule matching more distinct functions than this in one app is treated as non-specific noise. */
    public static final int LEARNED_MAX_FUNCTION_HITS = 20;

    /** Highest severity an LLM-learned rule may report (env MALIMITE_LEARNED_MAX_SEVERITY, default MEDIUM). */
    public static String learnedMaxSeverity() {
        String v = System.getenv("MALIMITE_LEARNED_MAX_SEVERITY");
        if (v != null && SEVERITIES.contains(v.trim().toUpperCase(Locale.ROOT))) return v.trim().toUpperCase(Locale.ROOT);
        return "MEDIUM";
    }

    /** {@code severity} lowered to {@code max} when it is more severe; unknown values are treated as the cap. */
    public static String capSeverity(String severity, String max) {
        int sev = SEVERITIES.indexOf(severity == null ? "" : severity.trim().toUpperCase(Locale.ROOT));
        int cap = SEVERITIES.indexOf(max);
        if (cap < 0) return severity;
        return sev < 0 || sev < cap ? SEVERITIES.get(cap) : SEVERITIES.get(sev);
    }

    /** CVSS ceiling that matches a severity label (CVSS v3 qualitative ranges). */
    public static double capCvss(double cvss, String cappedSeverity) {
        return switch (cappedSeverity) {
            case "HIGH" -> Math.min(cvss, 8.9);
            case "MEDIUM" -> Math.min(cvss, 6.9);
            case "LOW" -> Math.min(cvss, 3.9);
            case "INFO" -> 0.0;
            default -> cvss;
        };
    }
}
