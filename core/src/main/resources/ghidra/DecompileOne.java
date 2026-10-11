import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.symbol.Namespace;
import ghidra.util.task.ConsoleTaskMonitor;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * On-demand decompile of a few functions of an already-analyzed program.
 * Args: &lt;outFile&gt; &lt;query&gt; &lt;maxMatches&gt;
 * query = 0x-address (function containing it) or a case-insensitive substring of "Namespace::name".
 * Writes plain text ("// ns::name @ addr" header + C body per match); writes nothing when no match,
 * so the caller can tell "no match" from a crash. No org.json dependency on purpose.
 */
public class DecompileOne extends GhidraScript {

    private static final int DECOMPILE_TIMEOUT_SECS = 90;

    @Override
    protected void run() throws Exception {
        String[] a = getScriptArgs();
        if (a == null || a.length < 3) {
            printerr("Expected: <outFile> <query> <maxMatches>");
            return;
        }
        Path out = Path.of(a[0]);
        String query = a[1].trim();
        int max = Math.max(1, Math.min(Integer.parseInt(a[2].trim()), 10));

        List<Function> matches = new ArrayList<>();
        if (query.matches("(?i)0x[0-9a-f]{1,16}")) {
            Address addr = toAddr(query);
            Function f = addr == null ? null : getFunctionContaining(addr);
            if (f != null) matches.add(f);
        } else {
            String needle = query.toLowerCase(Locale.ROOT);
            FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
            while (it.hasNext() && matches.size() < max) {
                Function f = it.next();
                if (qualifiedName(f).toLowerCase(Locale.ROOT).contains(needle)) matches.add(f);
            }
        }
        if (matches.isEmpty()) {
            println("DecompileOne: no match for '" + query + "'");
            return;
        }

        DecompInterface di = new DecompInterface();
        StringBuilder sb = new StringBuilder();
        try {
            di.openProgram(currentProgram);
            for (Function f : matches) {
                sb.append("// ").append(qualifiedName(f)).append(" @ ").append(f.getEntryPoint()).append('\n');
                var res = di.decompileFunction(f, DECOMPILE_TIMEOUT_SECS, new ConsoleTaskMonitor());
                if (res != null && res.decompileCompleted()) {
                    sb.append(res.getDecompiledFunction().getC());
                } else {
                    sb.append("/* decompilation failed or timed out: ")
                      .append(res == null ? "null result" : res.getErrorMessage()).append(" */\n");
                }
                sb.append('\n');
            }
        } finally {
            di.dispose();
        }
        Files.writeString(out, sb.toString(), StandardCharsets.UTF_8);
    }

    private static String qualifiedName(Function f) {
        Namespace ns = f.getParentNamespace();
        String n = ns == null ? "" : ns.getName();
        return (n.isEmpty() || "Global".equals(n) ? "" : n + "::") + f.getName();
    }
}
