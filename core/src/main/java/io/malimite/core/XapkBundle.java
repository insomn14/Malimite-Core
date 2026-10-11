package io.malimite.core;

import net.dongliu.apk.parser.ApkFile;
import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.zip.Deflater;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

/**
 * Support for split-APK bundles ({@code .xapk}: a zip of {@code base.apk} plus {@code split_config.*.apk}, optionally
 * with a {@code manifest.json} and OBB expansion files).
 *
 * <p>The analysis pipeline (JADX, Droid ASC, validators, Ghidra for native libraries, the on-demand decompiler) works on
 * one APK, and in a bundle the interesting parts are spread out: DEX and the manifest are in the base, but the
 * {@code lib/arm64-v8a/*.so} files are in {@code split_config.arm64_v8a.apk}. So the bundle is first merged into one
 * ordinary APK: the base APK plus every entry the splits add. The result is for analysis only, it is not installable.
 *
 * <p>The input is untrusted: entry names are validated, the amount of data is capped (declared sizes can lie, so the
 * cap is enforced while copying), and OBB files are never read.
 */
public final class XapkBundle {

    private static final Logger log = LoggerFactory.getLogger(XapkBundle.class);

    private XapkBundle() {}

    /** Upper bound on the bytes of APK data we are willing to read from one bundle. */
    static final long MAX_BYTES = 2L * 1024 * 1024 * 1024;
    static final int MAX_APKS = 64;
    static final int MAX_ENTRIES = 200_000;

    /** What a merge produced. */
    public record Merged(Path apk, String base, List<String> splits, Path source) {}

    private static final Pattern CLASSES_DEX = Pattern.compile("classes(\\d*)\\.dex");
    private static final Pattern MANIFEST_SPLIT_ATTR = Pattern.compile("<manifest\\b[^>]*\\ssplit\\s*=");

    /** A zip that holds APKs but is not itself an APK (no root {@code AndroidManifest.xml}). */
    public static boolean isBundle(Path path) {
        try (ZipFile zf = new ZipFile(path.toFile())) {
            boolean hasApk = false;
            Enumeration<? extends ZipEntry> en = zf.entries();
            while (en.hasMoreElements()) {
                ZipEntry e = en.nextElement();
                if (e.isDirectory()) continue;
                if ("AndroidManifest.xml".equals(e.getName())) return false;
                if (e.getName().toLowerCase(Locale.ROOT).endsWith(".apk")) hasApk = true;
            }
            return hasApk;
        } catch (IOException | RuntimeException e) {
            return false;
        }
    }

    /** Merges the bundle into {@code outApk} (an ordinary APK) and reports what was used. */
    public static Merged merge(Path bundle, Path outApk) throws IOException {
        return merge(bundle, outApk, MAX_BYTES);
    }

    static Merged merge(Path bundle, Path outApk, long maxBytes) throws IOException {
        Path tmp = Files.createTempDirectory("malimite-xapk-");
        try {
            JSONObject manifest = null;
            List<String> apkNames = new ArrayList<>();
            List<Path> apkFiles = new ArrayList<>();
            long[] budget = {maxBytes};
            try (ZipFile zf = new ZipFile(bundle.toFile())) {
                int seen = 0;
                Enumeration<? extends ZipEntry> en = zf.entries();
                while (en.hasMoreElements()) {
                    ZipEntry e = en.nextElement();
                    if (++seen > MAX_ENTRIES) throw new IOException("Bundle has too many entries");
                    if (e.isDirectory()) continue;
                    String name = e.getName();
                    String lower = name.toLowerCase(Locale.ROOT);
                    if ("manifest.json".equals(lower)) {
                        manifest = parseManifestJson(readCapped(zf, e, 1 << 20));
                    } else if (lower.endsWith(".apk")) {
                        if (apkNames.size() >= MAX_APKS) throw new IOException("Bundle has more than " + MAX_APKS + " APKs");
                        requireSafe(name);
                        Path f = tmp.resolve(apkNames.size() + ".apk");
                        copyCapped(zf, e, f, budget);
                        apkNames.add(name);
                        apkFiles.add(f);
                    }
                    // everything else (OBB expansions, icons, ...) is deliberately never read
                }
            }
            if (apkNames.isEmpty()) throw new IOException("The bundle contains no .apk files");

            int baseIdx = chooseBase(apkNames, manifest, i -> isSplitApk(apkFiles.get(i)));
            List<Integer> splitIdx = new ArrayList<>();
            for (int i = 0; i < apkNames.size(); i++) if (i != baseIdx) splitIdx.add(i);
            splitIdx.sort((a, b) -> apkNames.get(a).compareTo(apkNames.get(b)));   // deterministic output

            Files.createDirectories(outApk.toAbsolutePath().getParent());
            int renamedDex = mergeInto(outApk, apkFiles.get(baseIdx), splitIdx.stream().map(apkFiles::get).toList(), budget);
            List<String> splitNames = splitIdx.stream().map(apkNames::get).toList();
            log.info("XAPK merged: base={} splits={} dexAddedFromSplits={} -> {}", apkNames.get(baseIdx), splitNames,
                    renamedDex, outApk);
            return new Merged(outApk, apkNames.get(baseIdx), splitNames, bundle);
        } finally {
            OnDemandDecompiler.deleteTree(tmp);
        }
    }

    // ── choosing the base APK ────────────────────────────────────────────────────────────────────────────────────

    /**
     * Index of the base APK. Order: manifest.json says so; a file named base.apk / base-master.apk; the only APK whose
     * manifest has no {@code split} attribute; the only APK whose file name does not look like a split.
     *
     * @param isSplit asks whether APK #i is a split according to its own AndroidManifest (null = unknown)
     */
    static int chooseBase(List<String> names, JSONObject manifest, java.util.function.IntFunction<Boolean> isSplit) {
        if (manifest != null) {
            JSONArray arr = manifest.optJSONArray("split_apks");
            if (arr != null) {
                for (int i = 0; i < arr.length(); i++) {
                    JSONObject o = arr.optJSONObject(i);
                    if (o != null && "base".equals(o.optString("id"))) {
                        int idx = indexOfFile(names, o.optString("file"));
                        if (idx >= 0) return idx;
                    }
                }
            }
            String pkg = manifest.optString("package_name", "");
            if (!pkg.isEmpty()) {
                int idx = indexOfFile(names, pkg + ".apk");
                if (idx >= 0) return idx;
            }
        }
        for (String wanted : new String[] {"base.apk", "base-master.apk"}) {
            int idx = indexOfFile(names, wanted);
            if (idx >= 0) return idx;
        }
        List<Integer> nonSplit = new ArrayList<>();
        for (int i = 0; i < names.size(); i++) if (Boolean.FALSE.equals(isSplit.apply(i))) nonSplit.add(i);
        if (nonSplit.size() == 1) return nonSplit.get(0);
        List<Integer> byName = new ArrayList<>();
        for (int i = 0; i < names.size(); i++) if (!looksLikeSplitName(names.get(i))) byName.add(i);
        if (byName.size() == 1) return byName.get(0);
        throw new IllegalArgumentException("Cannot tell which APK is the base (candidates: "
                + (nonSplit.isEmpty() ? names : nonSplit.stream().map(names::get).toList()) + ")");
    }

    private static int indexOfFile(List<String> names, String file) {
        if (file == null || file.isEmpty()) return -1;
        String want = baseName(file).toLowerCase(Locale.ROOT);
        for (int i = 0; i < names.size(); i++)
            if (baseName(names.get(i)).toLowerCase(Locale.ROOT).equals(want)) return i;
        return -1;
    }

    static boolean looksLikeSplitName(String name) {
        String n = baseName(name).toLowerCase(Locale.ROOT);
        return n.startsWith("split_") || n.startsWith("config.") || n.contains(".config.") || n.startsWith("split-");
    }

    private static String baseName(String path) {
        int s = path.lastIndexOf('/');
        return s >= 0 ? path.substring(s + 1) : path;
    }

    /** TRUE when the APK's AndroidManifest declares {@code split="..."}, FALSE when it does not, null when unreadable. */
    static Boolean isSplitApk(Path apk) {
        try (ApkFile f = new ApkFile(apk.toFile())) {
            return MANIFEST_SPLIT_ATTR.matcher(f.getManifestXml()).find();
        } catch (Exception | LinkageError e) {
            return null;
        }
    }

    // ── merging ──────────────────────────────────────────────────────────────────────────────────────────────────

    /** Writes base + the entries splits add. Returns how many DEX files came from splits. */
    private static int mergeInto(Path out, Path base, List<Path> splits, long[] budget) throws IOException {
        Set<String> names = new HashSet<>();
        int dexCount = 0, dexFromSplits = 0;
        try (ZipOutputStream zos = new ZipOutputStream(new BufferedOutputStream(Files.newOutputStream(out)))) {
            zos.setLevel(Deflater.BEST_SPEED);
            try (ZipFile zf = new ZipFile(base.toFile())) {
                var en = zf.entries();
                while (en.hasMoreElements()) {
                    ZipEntry e = en.nextElement();
                    if (e.isDirectory()) continue;
                    String n = e.getName();
                    requireSafe(n);
                    if (!names.add(n)) continue;
                    if (CLASSES_DEX.matcher(n).matches()) dexCount++;
                    put(zos, zf, e, n, budget);
                }
            }
            for (Path split : splits) {
                try (ZipFile zf = new ZipFile(split.toFile())) {
                    var en = zf.entries();
                    while (en.hasMoreElements()) {
                        ZipEntry e = en.nextElement();
                        if (e.isDirectory()) continue;
                        String n = e.getName();
                        requireSafe(n);
                        if (skippedFromSplit(n)) continue;
                        String target = n;
                        if (CLASSES_DEX.matcher(n).matches()) {          // feature split with code: continue the numbering
                            do { dexCount++; target = dexCount == 1 ? "classes.dex" : "classes" + dexCount + ".dex"; }
                            while (names.contains(target));
                            dexFromSplits++;
                        }
                        if (!names.add(target)) continue;                 // base (or an earlier split) wins on collisions
                        put(zos, zf, e, target, budget);
                    }
                }
            }
        }
        return dexFromSplits;
    }

    /** Split manifests/resource tables/signatures describe the split, not the app. */
    private static boolean skippedFromSplit(String name) {
        return "AndroidManifest.xml".equals(name) || "resources.arsc".equals(name)
                || name.startsWith("META-INF/") || "stamp-cert-sha256".equals(name);
    }

    private static void put(ZipOutputStream zos, ZipFile zf, ZipEntry e, String as, long[] budget) throws IOException {
        zos.putNextEntry(new ZipEntry(as));
        try (InputStream in = zf.getInputStream(e)) {
            byte[] buf = new byte[64 * 1024];
            int n;
            while ((n = in.read(buf)) > 0) {
                if ((budget[0] -= n) < 0) throw new IOException("Bundle is larger than the allowed size");
                zos.write(buf, 0, n);
            }
        }
        zos.closeEntry();
    }

    // ── safe reading ─────────────────────────────────────────────────────────────────────────────────────────────

    /** Rejects names that could escape a directory when the merged APK is unpacked later. */
    static void requireSafe(String name) throws IOException {
        if (name == null || name.isEmpty() || name.length() > 1024 || name.startsWith("/") || name.contains("\\")
                || name.indexOf('\0') >= 0)
            throw new IOException("Unsafe entry name in bundle: " + name);
        for (String part : name.split("/"))
            if (part.equals("..")) throw new IOException("Unsafe entry name in bundle: " + name);
    }

    private static void copyCapped(ZipFile zf, ZipEntry e, Path dest, long[] budget) throws IOException {
        try (InputStream in = zf.getInputStream(e); OutputStream os = Files.newOutputStream(dest)) {
            byte[] buf = new byte[64 * 1024];
            int n;
            while ((n = in.read(buf)) > 0) {
                if ((budget[0] -= n) < 0) throw new IOException("Bundle is larger than the allowed size");
                os.write(buf, 0, n);
            }
        }
    }

    private static byte[] readCapped(ZipFile zf, ZipEntry e, int max) throws IOException {
        try (InputStream in = zf.getInputStream(e)) {
            byte[] data = in.readNBytes(max + 1);
            if (data.length > max) throw new IOException("manifest.json is unreasonably large");
            return data;
        }
    }

    private static JSONObject parseManifestJson(byte[] data) {
        try {
            return new JSONObject(new String(data, java.nio.charset.StandardCharsets.UTF_8));
        } catch (RuntimeException ex) {
            log.warn("manifest.json in the bundle could not be parsed ({}); choosing the base APK by name/manifest", ex.getMessage());
            return null;
        }
    }
}
