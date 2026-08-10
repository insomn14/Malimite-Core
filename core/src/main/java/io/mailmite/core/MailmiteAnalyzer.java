package io.mailmite.core;

import com.google.gson.GsonBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.UUID;

/**
 * Headless entry point for end-to-end IPA / APK analysis.
 * Drop-in for CLI, REST workers, watcher daemons, and chat bots.
 *
 * <p>iOS: IpaValidator → IpaExtractor → InfoPlist → Macho → Ghidra → SqliteStore
 * <p>Android: ApkValidator → ApkExtractor → Manifest → JADX → (Ghidra on arm64 .so) → SqliteStore
 */
public class MailmiteAnalyzer {

    private static final Logger log = LoggerFactory.getLogger(MailmiteAnalyzer.class);

    public AnalysisResult analyze(AnalyzeOptions opts) throws Exception {
        PackagePlatform platform = PackagePlatform.detect(opts.packagePath());
        return switch (platform) {
            case IOS -> analyzeIos(opts);
            case ANDROID -> analyzeAndroid(opts);
        };
    }

    private AnalysisResult analyzeIos(AnalyzeOptions opts) throws Exception {
        long t0 = System.currentTimeMillis();
        String scanId = UUID.randomUUID().toString();
        log.info("scan={} platform=IOS package={} out={}", scanId, opts.packagePath(), opts.outputDir());

        if (opts.ghidraHome() == null)
            throw new IllegalArgumentException("ghidraHome required for iOS (.ipa) analysis");

        IpaValidator.validate(opts.packagePath());

        Path workDir = Files.createTempDirectory("mailmite-" + scanId + "-");
        IpaExtractor.ExtractionResult extraction = IpaExtractor.extract(opts.packagePath(), workDir);

        InfoPlist info = InfoPlist.parse(extraction.infoPlistPath());
        String execName = info.getExecutableName();
        String execPath = extraction.executablePath().toString();

        Files.createDirectories(opts.outputDir());
        Macho macho = new Macho(execPath, workDir.toString(), execName);

        if (macho.isUniversalBinary()) {
            List<String> archs = macho.getArchitectureStrings();
            String preferred = archs.stream()
                    .filter(a -> a.contains("ARM64"))
                    .findFirst()
                    .orElse(archs.get(0));
            log.info("Universal binary — selecting architecture: {}", preferred);
            macho.processUniversalMacho(preferred);
        }

        Path dbPath = opts.outputDir().resolve(scanId + ".sqlite");
        MobileProvision.ProvisionInfo provision = null;

        try (SqliteStore store = new SqliteStore(dbPath.toString())) {
            ResourceParser rp = new ResourceParser(store);
            parseResources(rp, extraction.appBundleDir());
            provision = parseMobileProvision(extraction.appBundleDir());

            CoreConfig config = CoreConfig.fromEnv(opts.ghidraHome());
            GhidraRunner runner = new GhidraRunner(execName, config, store);
            runner.decompile(execPath, opts.outputDir().toString(), macho);

            store.insertResourceString(
                    "MachOSecurityFlags",
                    macho.hasPie() ? "MH_PIE=1" : "MH_PIE=0",
                    "macho-flags");

            try {
                int vulnCount = new VulnerabilityScanner().scan(store, execName, PackagePlatform.IOS);
                log.info("VulnerabilityScanner found {} finding(s)", vulnCount);
            } catch (StackOverflowError e) {
                log.error("VulnerabilityScanner StackOverflowError — skipping rule scan");
            } catch (Exception e) {
                log.warn("VulnerabilityScanner failed — {}", e.getMessage());
            }

            runAssessmentIfEnabled(opts, store, execName, PackagePlatform.IOS);
            runLlmIfEnabled(opts, store, execName, macho.isSwift(), PackagePlatform.IOS);
        }

        saveScanJsonIos(opts.outputDir().resolve("scan.json"), scanId, info, macho, opts, dbPath, provision);

        long dt = System.currentTimeMillis() - t0;
        log.info("scan={} done in {}ms  db={}", scanId, dt, dbPath);
        return new AnalysisResult(scanId, opts.outputDir(), dt, dbPath);
    }

    private AnalysisResult analyzeAndroid(AnalyzeOptions opts) throws Exception {
        long t0 = System.currentTimeMillis();
        String scanId = UUID.randomUUID().toString();
        log.info("scan={} platform=ANDROID package={} out={}", scanId, opts.packagePath(), opts.outputDir());

        ApkValidator.validate(opts.packagePath());

        Path workDir = Files.createTempDirectory("mailmite-apk-" + scanId + "-");
        ApkExtractor.ExtractionResult extraction = ApkExtractor.extract(opts.packagePath(), workDir);
        AndroidManifestParser.ManifestInfo manifest = AndroidManifestParser.parse(opts.packagePath());

        String execName = manifest.applicationId();
        Files.createDirectories(opts.outputDir());
        Path dbPath = opts.outputDir().resolve(scanId + ".sqlite");
        Path jadxOut = opts.outputDir().resolve("jadx-" + scanId);

        List<String> abis = ApkExtractor.detectAbis(extraction.nativeLibs());
        List<Path> arm64Libs = ApkExtractor.preferArm64NativeLibs(extraction.nativeLibs());
        List<String> nativeDecompiled = new java.util.ArrayList<>();
        String nativeSkippedReason = null;

        try (SqliteStore store = new SqliteStore(dbPath.toString())) {
            JadxRunner jadx = new JadxRunner(opts.jadxHome());
            Path sources = jadx.decompile(opts.packagePath(), jadxOut);
            try {
                JadxIngest.ingest(sources, store, execName, manifest, extraction);
            } catch (StackOverflowError e) {
                // StackOverflowError is an Error — must not abort the whole Android scan.
                log.error("JadxIngest StackOverflowError — continuing with partial ingest");
            }

            if (arm64Libs.isEmpty()) {
                if (!extraction.nativeLibs().isEmpty()) {
                    nativeSkippedReason = "no_arm64_v8a_libs";
                    log.info("Native libs present ({}) but none under lib/arm64-v8a — skipping Ghidra native phase",
                            abis);
                } else {
                    nativeSkippedReason = "no_native_libs";
                }
            } else {
                // ELF protection flags (PIC / canary / debug) — no Ghidra required
                for (Path so : arm64Libs)
                    ElfNativeProtections.ingest(store, so);

                if (opts.ghidraHome() == null) {
                    nativeSkippedReason = "ghidra_home_unset";
                    log.warn("APK has {} arm64-v8a .so lib(s) but ghidraHome is unset — " +
                            "ELF protections checked; skipping native Ghidra decompile. " +
                            "Set GHIDRA_HOME for full Android native coverage.",
                            arm64Libs.size());
                } else {
                    CoreConfig config = CoreConfig.fromEnv(opts.ghidraHome());
                    for (Path so : arm64Libs) {
                        String libName = so.getFileName().toString();
                        try {
                            Path projDir = opts.outputDir().resolve("ghidra-native-" + scanId + "-" + libName);
                            Files.createDirectories(projDir);
                            BinaryIdentity identity = BinaryIdentity.forAndroidNativeLib(execName, libName);
                            GhidraRunner runner = new GhidraRunner(
                                    execName + "_" + libName.replace('.', '_'), config, store);
                            runner.decompile(so.toString(), projDir.toString(), identity);
                            nativeDecompiled.add(libName);
                            log.info("Native Ghidra complete for {}", libName);
                        } catch (Exception e) {
                            log.warn("Native Ghidra failed for {}: {}", libName, e.getMessage());
                        }
                    }
                    if (nativeDecompiled.isEmpty())
                        nativeSkippedReason = "ghidra_native_failed";
                }
            }

            try {
                int vulnCount = new VulnerabilityScanner().scan(store, execName, PackagePlatform.ANDROID);
                log.info("VulnerabilityScanner found {} finding(s)", vulnCount);
            } catch (StackOverflowError e) {
                log.error("VulnerabilityScanner StackOverflowError — skipping rule scan");
            } catch (Exception e) {
                log.warn("VulnerabilityScanner failed — {}", e.getMessage());
            }

            runAssessmentIfEnabled(opts, store, execName, PackagePlatform.ANDROID);
            runLlmIfEnabled(opts, store, execName, false, PackagePlatform.ANDROID);
        }

        saveScanJsonAndroid(opts.outputDir().resolve("scan.json"), scanId, manifest, opts, dbPath,
                extraction, abis, nativeDecompiled, nativeSkippedReason);

        long dt = System.currentTimeMillis() - t0;
        log.info("scan={} done in {}ms  db={}", scanId, dt, dbPath);
        return new AnalysisResult(scanId, opts.outputDir(), dt, dbPath);
    }

    private void runAssessmentIfEnabled(AnalyzeOptions opts, SqliteStore store, String execName,
                                        PackagePlatform platform) {
        if (!opts.assessmentEnabled()) return;
        try {
            int n = new AssessmentScanner().scan(store, execName, platform);
            log.info("AssessmentScanner recorded {} control(s)", n);
        } catch (Exception e) {
            log.warn("AssessmentScanner failed — {}", e.getMessage());
        }
    }

    private void runLlmIfEnabled(AnalyzeOptions opts, SqliteStore store, String execName,
                                 boolean isSwift, PackagePlatform platform) {
        if (!opts.llmEnabled()) return;
        try {
            LlmProvider llmProvider = LlmProviderFactory.create(opts.llmConfig());
            if (llmProvider != null) {
                new LlmEnricher(llmProvider, opts.llmMode(), LlmCache.NOOP, isSwift, platform)
                        .enrich(store, execName);
            } else {
                log.warn("llmEnabled=true but LLM_PROVIDER=none — skipping enrichment");
            }
        } catch (Exception e) {
            log.warn("LLM enrichment skipped — {}", e.getMessage());
        }
    }

    private void parseResources(ResourceParser rp, Path appBundleDir) {
        try (var walk = Files.walk(appBundleDir)) {
            walk.filter(Files::isRegularFile)
                .forEach(p -> {
                    String name = p.getFileName().toString().toLowerCase();
                    if (ResourceParser.isResource(name)) {
                        try (InputStream in = Files.newInputStream(p)) {
                            rp.parseResourceForStrings(in, p.toString());
                        } catch (IOException e) {
                            log.warn("Failed to parse resource {}: {}", p, e.getMessage());
                        }
                    }
                });
        } catch (IOException e) {
            log.warn("Resource scan failed: {}", e.getMessage());
        }
    }

    private MobileProvision.ProvisionInfo parseMobileProvision(Path appBundleDir) {
        Path provision = appBundleDir.resolve("embedded.mobileprovision");
        if (!Files.exists(provision)) {
            log.debug("No embedded.mobileprovision found");
            return null;
        }
        try {
            byte[] data = Files.readAllBytes(provision);
            MobileProvision.ProvisionInfo info = MobileProvision.parse(data);
            if (info != null)
                log.info("Provisioning profile: name={} team={} expiry={}",
                        info.profileName(), info.teamId(), info.expiryDate());
            return info;
        } catch (IOException e) {
            log.warn("Could not read mobileprovision: {}", e.getMessage());
            return null;
        }
    }

    private void saveScanJsonIos(Path target, String scanId, InfoPlist info,
                                 Macho macho, AnalyzeOptions opts, Path dbPath,
                                 MobileProvision.ProvisionInfo provision) {
        try {
            var meta = new java.util.LinkedHashMap<String, Object>();
            meta.put("scanId", scanId);
            meta.put("platform", "IOS");
            meta.put("bundleExecutable", info.getExecutableName());
            meta.put("bundleIdentifier", info.getBundleIdentifier());
            meta.put("packageName", info.getBundleIdentifier());
            meta.put("isSwift", macho.isSwift());
            meta.put("isUniversal", macho.isUniversalBinary());
            meta.put("architectures", macho.getArchitectureStrings());
            meta.put("dbPath", dbPath.toString());
            meta.put("ipaPath", opts.packagePath().toString());
            meta.put("packagePath", opts.packagePath().toString());
            if (provision != null) {
                meta.put("bundleTeamId", provision.teamId());
                meta.put("provisioningProfile", provision.profileName());
                meta.put("provisioningExpiry", provision.expiryDate());
            }
            writeJson(target, meta);
        } catch (Exception e) {
            log.warn("Could not write scan.json", e);
        }
    }

    private void saveScanJsonAndroid(Path target, String scanId,
                                     AndroidManifestParser.ManifestInfo manifest,
                                     AnalyzeOptions opts, Path dbPath,
                                     ApkExtractor.ExtractionResult extraction,
                                     List<String> abis,
                                     List<String> nativeDecompiled,
                                     String nativeSkippedReason) {
        try {
            var meta = new java.util.LinkedHashMap<String, Object>();
            meta.put("scanId", scanId);
            meta.put("platform", "ANDROID");
            meta.put("bundleExecutable", manifest.applicationId());
            meta.put("bundleIdentifier", manifest.applicationId());
            meta.put("packageName", manifest.applicationId());
            meta.put("applicationId", manifest.applicationId());
            meta.put("versionName", manifest.versionName());
            meta.put("versionCode", manifest.versionCode());
            meta.put("minSdk", manifest.minSdk());
            meta.put("targetSdk", manifest.targetSdk());
            meta.put("debuggable", manifest.debuggable());
            meta.put("allowBackup", manifest.allowBackup());
            meta.put("usesCleartextTraffic", manifest.usesCleartextTraffic());
            meta.put("isSwift", false);
            meta.put("isUniversal", false);
            meta.put("architectures", abis);
            meta.put("preferredNativeAbi", ApkExtractor.PREFERRED_ABI);
            meta.put("nativeLibCount", extraction.nativeLibs().size());
            meta.put("nativeLibsDecompiled", nativeDecompiled);
            if (nativeSkippedReason != null)
                meta.put("nativeSkippedReason", nativeSkippedReason);
            meta.put("dexCount", extraction.dexFiles().size());
            meta.put("dbPath", dbPath.toString());
            meta.put("ipaPath", opts.packagePath().toString());
            meta.put("packagePath", opts.packagePath().toString());
            writeJson(target, meta);
        } catch (Exception e) {
            log.warn("Could not write scan.json", e);
        }
    }

    private void writeJson(Path target, java.util.Map<String, Object> meta) throws IOException {
        String json = new GsonBuilder().setPrettyPrinting().create().toJson(meta);
        Files.writeString(target, json);
        log.info("Scan metadata written to {}", target);
    }
}
