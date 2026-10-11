package io.malimite.core;

import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.regex.Pattern;

/**
 * One-shot, on-demand decompilation of a single class/function for the web AI assistant.
 *
 * <p>Usage: {@code java -cp malimite-cli.jar io.malimite.core.OnDemandDecompiler <scan-dir> asc|jadx|ghidra <target> [--lib x.so]}
 * (asc/jadx: dotted class name, Android only; ghidra: function-name substring or 0x address, iOS or Android .so)
 *
 * <p>Prints exactly one JSON object on stdout ({@code ok, tool, target, code, error}); logs go to stderr.
 * Reads {@code scan.json} for the original package path and platform. The target is validated here too:
 * the caller is not trusted to have sanitised model-provided input.
 */
public final class OnDemandDecompiler {

    private static final Pattern CLASS = Pattern.compile("^[A-Za-z_$][\\w$]*(\\.[A-Za-z_$][\\w$]*)*$");
    // first char must not be '-': analyzeHeadless would parse it as one of its own options
    private static final Pattern GHIDRA_TARGET = Pattern.compile("^(0x[0-9a-fA-F]{1,16}|[\\w$@<:\\[][\\w\\-\\[\\] +:.<>$@]{0,199})$");
    private static final Pattern LIB = Pattern.compile("^\\w[\\w.\\-]{0,99}\\.so$");
    private static final int MAX_CODE_CHARS = 1_000_000;

    private OnDemandDecompiler() {}

    public static void main(String[] args) {
        JSONObject res;
        try {
            if (args.length < 3) throw new IllegalArgumentException(
                    "Usage: OnDemandDecompiler <scan-dir> asc|jadx <class>");
            String lib = args.length >= 5 && "--lib".equals(args[3]) ? args[4] : "";
            res = run(Path.of(args[0]), args[1], args[2], lib);
        } catch (Exception e) {
            String tool = args.length > 1 ? args[1] : "";
            String target = args.length > 2 ? args[2] : "";
            res = result(false, tool, target, "", e.getMessage() == null ? e.toString() : e.getMessage());
        }
        System.out.println(res);
    }

    static JSONObject run(Path scanDir, String tool, String target, String lib) throws Exception {
        if (!"asc".equals(tool) && !"jadx".equals(tool) && !"ghidra".equals(tool))
            return result(false, tool, target, "", "unknown tool '" + tool + "' (expected asc|jadx|ghidra)");
        if ("ghidra".equals(tool)) return runGhidra(scanDir, target, lib);
        if (!CLASS.matcher(target).matches() || target.length() > 300)
            return result(false, tool, target, "", "invalid class name (use dotted form, e.g. com.foo.Bar or com.foo.Bar$Inner)");

        JSONObject meta = new JSONObject(Files.readString(scanDir.resolve("scan.json"), StandardCharsets.UTF_8));
        if (!"ANDROID".equalsIgnoreCase(meta.optString("platform")))
            return result(false, tool, target, "", tool + " only supports Android scans");
        Path apk = packagePath(scanDir, meta);

        String code;
        if ("asc".equals(tool)) {
            code = new AscRunner(null).getClass(apk, "L" + target.replace('.', '/') + ";");
        } else {
            Path tmp = Files.createTempDirectory("malimite-jadx1-");
            try {
                code = new JadxRunner(null).decompileClass(apk, target, tmp);
            } finally {
                deleteTree(tmp);
            }
        }
        if (code == null || code.isBlank())
            return result(false, tool, target, "", "empty result (class not found? check the exact name with list_classes)");
        if (code.length() > MAX_CODE_CHARS) code = code.substring(0, MAX_CODE_CHARS) + "\n/* truncated */\n";
        return result(true, tool, target, code, "");
    }

    private static JSONObject runGhidra(Path scanDir, String target, String lib) throws Exception {
        if (!GHIDRA_TARGET.matcher(target).matches())
            return result(false, "ghidra", target, "", "invalid target (function name substring or 0x address)");
        JSONObject meta = new JSONObject(Files.readString(scanDir.resolve("scan.json"), StandardCharsets.UTF_8));
        boolean android = "ANDROID".equalsIgnoreCase(meta.optString("platform"));
        if (android && !LIB.matcher(lib).matches())
            return result(false, "ghidra", target, "", "Android native decompilation needs --lib <name>.so");
        String code = GhidraOnDemand.decompile(scanDir, meta, packagePath(scanDir, meta), target, android ? lib : "");
        if (code == null || code.isBlank())
            return result(false, "ghidra", target, "", "no function matching '" + target
                    + "' (try a shorter substring of the name, or a 0x address)");
        if (code.length() > MAX_CODE_CHARS) code = code.substring(0, MAX_CODE_CHARS) + "\n/* truncated */\n";
        return result(true, "ghidra", target, code, "");
    }

    /** scan.json path first, then the web service's upload next to it. */
    static Path packagePath(Path scanDir, JSONObject meta) {
        String raw = meta.optString("packagePath", meta.optString("ipaPath", ""));
        if (!raw.isBlank() && Files.isRegularFile(Path.of(raw))) return Path.of(raw);
        for (String n : new String[] {"upload.apk", "upload.ipa"}) {
            Path p = scanDir.resolve(n);
            if (Files.isRegularFile(p)) return p;
        }
        throw new IllegalStateException("original package not found (scan.json packagePath missing on disk)");
    }

    static JSONObject result(boolean ok, String tool, String target, String code, String error) {
        return new JSONObject().put("ok", ok).put("tool", tool).put("target", target)
                .put("code", code).put("error", error);
    }

    static void deleteTree(Path root) {
        try (var walk = Files.walk(root)) {
            walk.sorted(java.util.Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
        } catch (Exception ignored) {
            // best-effort temp cleanup
        }
    }
}
