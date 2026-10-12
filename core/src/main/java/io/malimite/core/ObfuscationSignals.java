package io.malimite.core;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Structural detection of bytecode-interpreter ("VM") obfuscation in Ghidra pseudocode.
 *
 * <p>Signature: a function that reads an opcode byte, compares it against many distinct constants and advances a
 * byte pointer in a loop. Measured on a real iOS crackme: 43 of 156 functions are such interpreters (every one has
 * exactly 9 distinct opcodes); all other functions have at most 5 and none of its Objective-C methods match. The
 * checks that app performs are hidden inside the bytecode, so "no jailbreak detection found" is not conclusive.
 *
 * <p>This only ever lowers the confidence of an "absent" claim; it never hides a finding.
 */
public final class ObfuscationSignals {

    private ObfuscationSignals() {}

    /** Distinct opcode constants an interpreter loop compares its opcode byte against. */
    static final int MIN_OPCODES = 6;
    /** Byte-pointer advances ({@code pbVar5 = pbVar5 + 1;}) in the same function. */
    static final int MIN_ADVANCES = 3;
    /** A single such function can be a decoder; several are an obfuscation scheme. */
    static final int MIN_FUNCTIONS = 3;

    private static final Pattern OPCODE_COMPARE =
            Pattern.compile("\\b[bc]Var\\d+\\s*(?:==|!=|<=|>=|<|>)\\s*(0x[0-9a-fA-F]+|\\d+)");
    private static final Pattern POINTER_ADVANCE =
            Pattern.compile("\\bp[bc]Var\\d+\\s*=\\s*p[bc]Var\\d+\\s*\\+\\s*\\d+\\s*;");
    private static final Pattern LOOP =
            Pattern.compile("\\b(?:while\\s*\\(\\s*(?:true|1)\\s*\\)|do\\s*\\{|LAB_\\w+:)");

    /** {@code vmFunctions} interpreter-like functions, {@code samples} the first few names. */
    public record Result(int vmFunctions, List<String> samples) {
        public boolean bytecodeVm() {
            return vmFunctions >= MIN_FUNCTIONS;
        }

        /** One line explaining why an absence claim is uncertain; empty when there is nothing to caveat. */
        public String caveat() {
            if (!bytecodeVm()) return "";
            return "The app contains " + vmFunctions + " bytecode-interpreter functions (e.g. "
                    + String.join(", ", samples) + "): the check may be hidden in obfuscated bytecode, "
                    + "so its absence is not conclusive.";
        }
    }

    public static final Result NONE = new Result(0, List.of());

    public static Result analyze(Collection<SqliteStore.DecompilationResult> fns) {
        int n = 0;
        List<String> samples = new ArrayList<>();
        for (var fn : fns) {
            if (!looksLikeInterpreter(fn.decompiledCode())) continue;
            n++;
            if (samples.size() < 3) samples.add(fn.functionName());
        }
        return n == 0 ? NONE : new Result(n, List.copyOf(samples));
    }

    static boolean looksLikeInterpreter(String body) {
        if (body == null || body.length() < 200) return false;
        if (!LOOP.matcher(body).find()) return false;
        Set<String> opcodes = new HashSet<>();
        Matcher m = OPCODE_COMPARE.matcher(body);
        while (m.find()) opcodes.add(m.group(1));
        if (opcodes.size() < MIN_OPCODES) return false;
        int advances = 0;
        Matcher a = POINTER_ADVANCE.matcher(body);
        while (a.find()) advances++;
        return advances >= MIN_ADVANCES;
    }
}
