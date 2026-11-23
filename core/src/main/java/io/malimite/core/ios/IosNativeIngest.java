package io.malimite.core.ios;

import io.malimite.core.SqliteStore;
import io.malimite.core.SyntaxParser;
import org.json.JSONArray;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Ghidra-free iOS ingest: mmaps the arm64 Mach-O and fills the same SqliteStore tables the Ghidra path fills
 * (Classes, Functions, MachoStrings, EntryPoints, FunctionReferences), so rules, reports, the LLM stage and the
 * Functions Explorer work unchanged. Origin is {@link #ORIGIN}.
 */
public final class IosNativeIngest {

    private static final Logger log = LoggerFactory.getLogger(IosNativeIngest.class);

    public static final String ORIGIN = "NATIVE";
    static final String IMPORTS_CLASS = "Imports";
    private static final int CHUNK = 4_096;
    /** Cap on unnamed (sub_*) functions stored; ObjC methods and symbol-named functions are never capped. */
    private static final int MAX_UNNAMED = 100_000;

    // Same entry-point names GhidraRunner marks (core/GhidraRunner.ENTRY_POINT_NAMES).
    private static final java.util.Set<String> ENTRY_POINT_NAMES = java.util.Set.of(
            "main", "applicationDidFinishLaunching:", "application:didFinishLaunchingWithOptions:",
            "applicationDidBecomeActive:", "applicationWillTerminate:", "+initialize", "+load");

    public record Result(int strings, int imports, int classes, int functions, int withCode) {}

    private IosNativeIngest() {}

    /** @param libraryPrefixes class-name prefixes treated as system/third-party libraries (empty code, class {@code Libraries}) */
    public static Result ingest(Path macho, SqliteStore store, String executableName, List<String> libraryPrefixes)
            throws IOException {
        long t0 = System.currentTimeMillis();
        try (MachOImage img = MachOImage.open(macho)) {
            if (img.encrypted)
                throw new IOException("executable is FairPlay-encrypted (cryptid=1); decrypt it before scanning");
            int strings = ingestStrings(img, store, executableName);
            int imports = ingestImports(img, store, executableName);
            ObjcMetadata objc = new ObjcMetadata(img);
            int[] counts = ingestFunctions(img, objc, store, executableName, libraryPrefixes);
            log.info("Native iOS ingest: {} strings, {} imports, {} classes, {} functions ({} with code) in {} ms",
                    strings, imports, counts[0], counts[1], counts[2], System.currentTimeMillis() - t0);
            return new Result(strings, imports, counts[0], counts[1], counts[2]);
        }
    }

    private static int ingestStrings(MachOImage img, SqliteStore store, String exec) {
        List<String[]> batch = new ArrayList<>();
        List<StringTable.Entry> all = StringTable.extract(img);
        for (StringTable.Entry e : all) {
            batch.add(new String[] {"0x" + Long.toHexString(e.addr()), e.value(), e.section(), ""});
            if (batch.size() >= 20_000) { store.insertMachoStrings(batch, exec); batch.clear(); }
        }
        if (!batch.isEmpty()) store.insertMachoStrings(batch, exec);
        return all.size();
    }

    private static int ingestImports(MachOImage img, SqliteStore store, String exec) {
        List<String> names = img.imports();
        if (names.isEmpty()) return 0;
        List<SqliteStore.DecompilationResult> rows = new ArrayList<>();
        for (String n : names) rows.add(new SqliteStore.DecompilationResult(n, IMPORTS_CLASS, "", exec, ORIGIN));
        store.insertFunctionDecompilations(rows);
        store.insertClass(IMPORTS_CLASS, new JSONArray(names).toString(), exec);
        return names.size();
    }

    /** Names of the symbol-table functions (defined, in a section), keyed by address, without the Mach-O underscore. */
    private static Map<Long, String> definedSymbols(MachOImage img) {
        Map<Long, String> out = new HashMap<>();
        for (MachOImage.Symbol s : img.symbols()) {
            if ((s.type() & 0x0e) != 0x0e || s.sect() == 0 || s.addr() == 0) continue;
            String n = s.name().startsWith("_") ? s.name().substring(1) : s.name();
            out.putIfAbsent(s.addr(), n);
        }
        return out;
    }

    private record Item(long start, List<ObjcMetadata.Method> methods, String symbol, SwiftTypes.Method swift, Lifter.Lifted lifted) {}

    /** Returns {classes, functions, functionsWithCode}. */
    private static int[] ingestFunctions(MachOImage img, ObjcMetadata objc, SqliteStore store, String exec,
                                         List<String> libs) {
        Map<String, JSONArray> classToFunctions = new LinkedHashMap<>();
        Set<String> seen = new HashSet<>();
        Map<Long, String> symbols = definedSymbols(img);
        StubResolver stubs = new StubResolver(img, objc);
        Lifter lifter = new Lifter(img, objc, stubs, symbols);
        SwiftTypes swiftTypes = new SwiftTypes(img);
        int[] withCode = {0};
        int[] unnamedKept = {0};
        Set<Long> handled = new HashSet<>();

        MachOImage.Section text = img.section("__text");
        long[] all = img.functionStarts;
        long[] starts = text == null ? new long[0]
                : java.util.Arrays.stream(all).filter(a -> a >= text.addr() && a < text.addr() + text.size()).toArray();
        long textEnd = text == null ? 0 : text.addr() + text.size();
        final long[] st = starts;

        for (int c0 = 0; c0 < st.length; c0 += CHUNK) {
            int c1 = Math.min(st.length, c0 + CHUNK);
            Item[] items = java.util.stream.IntStream.range(c0, c1).parallel().mapToObj(i -> {
                long start = st[i], end = i + 1 < st.length ? st[i + 1] : textEnd;
                List<ObjcMetadata.Method> ms = objc.allByImp.get(start);
                SwiftTypes.Method sw = ms == null ? swiftTypes.byImp.get(start) : null;
                boolean allLib = ms != null ? ms.stream().allMatch(m -> isLib(libs, m.cls()))
                        : sw != null && isLib(libs, sw.cls());
                Lifter.Lifted l = allLib ? null : lifter.lift(start, end, ms != null);
                return new Item(start, ms, symbols.get(start), sw, l);
            }).toArray(Item[]::new);

            List<SqliteStore.DecompilationResult> rows = new ArrayList<>();
            List<SyntaxParser.FunctionRefResult> refs = new ArrayList<>();
            for (Item it : items) {
                if (it.methods() != null) {
                    handled.add(it.start());
                    for (ObjcMetadata.Method m : it.methods())
                        addMethod(m, it.lifted(), exec, libs, seen, rows, refs, classToFunctions, store, withCode);
                } else if (it.swift() != null && it.symbol() == null) {
                    addSwift(it.swift(), it.lifted(), exec, libs, seen, rows, refs, classToFunctions, withCode);
                } else if (it.symbol() != null || (it.lifted() != null && it.lifted().interesting() && unnamedKept[0] < MAX_UNNAMED)) {
                    String fn = it.symbol() != null ? it.symbol() : "sub_" + Long.toHexString(it.start());
                    if (it.symbol() == null) unnamedKept[0]++;
                    if (!seen.add("Global\0" + fn)) continue;
                    String code = "// Class: Global\n// Function: " + fn + "\n\n" + it.lifted().body();
                    rows.add(new SqliteStore.DecompilationResult(fn, "Global", code, exec, ORIGIN));
                    classToFunctions.computeIfAbsent("Global", k -> new JSONArray()).put(fn);
                    for (Lifter.Ref r : it.lifted().refs())
                        refs.add(new SyntaxParser.FunctionRefResult(fn, "Global", r.target(), r.targetClass(), r.line(), exec));
                    withCode[0]++;
                    if ("main".equals(fn)) store.insertEntryPoint(fn, "Global", exec);
                }
            }
            if (!rows.isEmpty()) store.insertFunctionDecompilations(rows);
            if (!refs.isEmpty()) store.insertFunctionReferences(refs);
        }

        // ObjC methods whose implementation was not a __text function start: name only
        List<SqliteStore.DecompilationResult> rows = new ArrayList<>();
        for (ObjcMetadata.Method m : objc.methods) {
            if (handled.contains(m.imp())) continue;
            addMethod(m, null, exec, libs, seen, rows, new ArrayList<>(), classToFunctions, store, withCode);
        }
        if (!rows.isEmpty()) store.insertFunctionDecompilations(rows);

        for (Map.Entry<String, JSONArray> e : classToFunctions.entrySet())
            store.insertClass(e.getKey(), e.getValue().toString(), exec);
        return new int[] {classToFunctions.size(), seen.size(), withCode[0]};
    }

    /** A Swift class method known only from its vtable slot: {@code Module.Type} / {@code getter_3}. */
    private static void addSwift(SwiftTypes.Method m, Lifter.Lifted lifted, String exec, List<String> libs,
                                 Set<String> seen, List<SqliteStore.DecompilationResult> rows,
                                 List<SyntaxParser.FunctionRefResult> refs, Map<String, JSONArray> classToFunctions,
                                 int[] withCode) {
        String fn = m.functionName();
        boolean lib = isLib(libs, m.cls());
        String parent = lib ? "Libraries" : m.cls();
        String name = lib ? m.cls() + "::" + fn : fn;
        if (!seen.add(parent + "\0" + name)) return;
        String code = "";
        if (!lib && lifted != null) {
            code = "// Class: " + m.cls() + "\n// Function: " + fn + "\n\n"
                    + (lifted.body().isEmpty() ? "// no resolved operations\n" : lifted.body());
            for (Lifter.Ref r : lifted.refs())
                refs.add(new SyntaxParser.FunctionRefResult(fn, m.cls(), r.target(), r.targetClass(), r.line(), exec));
            withCode[0]++;
        }
        rows.add(new SqliteStore.DecompilationResult(name, parent, code, exec, ORIGIN));
        classToFunctions.computeIfAbsent(parent, k -> new JSONArray()).put(name);
    }

    private static boolean isLib(List<String> libs, String cls) {
        return libs.stream().anyMatch(l -> cls.equals(l) || cls.startsWith(l) || cls.contains("/" + l));
    }

    private static void addMethod(ObjcMetadata.Method m, Lifter.Lifted lifted, String exec, List<String> libs,
                                  Set<String> seen, List<SqliteStore.DecompilationResult> rows,
                                  List<SyntaxParser.FunctionRefResult> refs, Map<String, JSONArray> classToFunctions,
                                  SqliteStore store, int[] withCode) {
        String base = (m.classMethod() ? "+" : "") + m.selector();
        String fn = m.category() != null ? base + " (" + m.category() + ")" : base;
        String cls = m.cls();
        boolean lib = isLib(libs, cls);
        String parent = lib ? "Libraries" : cls;
        String name = lib ? cls + "::" + fn : fn;
        if (!seen.add(parent + "\0" + name)) return;  // PK (name, parent, exec) must stay unique
        String code = "";
        if (!lib && lifted != null) {
            code = "// Class: " + cls + "\n// Function: " + fn + "\n\n"
                    + (lifted.body().isEmpty() ? "// no resolved operations\n" : lifted.body());
            for (Lifter.Ref r : lifted.refs())
                refs.add(new SyntaxParser.FunctionRefResult(fn, cls, r.target(), r.targetClass(), r.line(), exec));
            withCode[0]++;
        }
        rows.add(new SqliteStore.DecompilationResult(name, parent, code, exec, ORIGIN));
        classToFunctions.computeIfAbsent(parent, k -> new JSONArray()).put(name);
        if (!lib && ENTRY_POINT_NAMES.contains(base)) store.insertEntryPoint(base, cls, exec);
    }
}
