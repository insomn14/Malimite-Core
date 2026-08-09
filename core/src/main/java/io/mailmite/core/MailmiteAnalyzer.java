package io.mailmite.core;

import com.google.gson.GsonBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Headless entry point for end-to-end IPA analysis.
 * Drop-in for CLI, REST workers, watcher daemons, and chat bots.
 *
 * Pipeline:
 *   IpaValidator → IpaExtractor → InfoPlist → Macho → ResourceParser →
 *   MobileProvision → GhidraRunner → SqliteStore
 */
public class MailmiteAnalyzer {

    private static final Logger log = LoggerFactory.getLogger(MailmiteAnalyzer.class);

    public AnalysisResult analyze(AnalyzeOptions opts) throws Exception {
        long   t0     = System.currentTimeMillis();
        String scanId = UUID.randomUUID().toString();
        log.info("scan={} ipa={} out={}", scanId, opts.ipaPath(), opts.outputDir());

        // ── 1. validate ───────────────────────────────────────────────────────
        IpaValidator.validate(opts.ipaPath());

        // ── 2. extract IPA ────────────────────────────────────────────────────
        Path workDir = Files.createTempDirectory("mailmite-" + scanId + "-");
        IpaExtractor.ExtractionResult extraction = IpaExtractor.extract(opts.ipaPath(), workDir);

        // ── 3. parse Info.plist ───────────────────────────────────────────────
        InfoPlist info     = InfoPlist.parse(extraction.infoPlistPath());
        String execName    = info.getExecutableName();
        String execPath    = extraction.executablePath().toString();

        // ── 4. parse Mach-O (Universal binary handling) ───────────────────────
        Files.createDirectories(opts.outputDir());
        Macho macho = new Macho(execPath, workDir.toString(), execName);

        if (macho.isUniversalBinary()) {
            List<String> archs = macho.getArchitectureStrings();
            String preferred   = archs.stream()
                    .filter(a -> a.contains("ARM64"))
                    .findFirst()
                    .orElse(archs.get(0));
            log.info("Universal binary — selecting architecture: {}", preferred);
            macho.processUniversalMacho(preferred);
        }

        // ── 5. open SQLite store ──────────────────────────────────────────────
        Path dbPath = opts.outputDir().resolve(scanId + ".sqlite");
        MobileProvision.ProvisionInfo provision = null;

        try (SqliteStore store = new SqliteStore(dbPath.toString())) {

            // ── 6. parse resource files in app bundle ─────────────────────────
            ResourceParser rp = new ResourceParser(store);
            parseResources(rp, extraction.appBundleDir());

            // ── 7. parse embedded.mobileprovision ─────────────────────────────
            provision = parseMobileProvision(extraction.appBundleDir());

            // ── 8. run Ghidra ─────────────────────────────────────────────────
            CoreConfig    config = CoreConfig.fromEnv(opts.ghidraHome());
            GhidraRunner  runner = new GhidraRunner(execName, config, store);
            runner.decompile(execPath, opts.outputDir().toString(), macho);

            // ── 8a. Mach-O security flags for static rules (e.g. MASTG-TEST-0228)
            store.insertResourceString(
                    "MachOSecurityFlags",
                    macho.hasPie() ? "MH_PIE=1" : "MH_PIE=0",
                    "macho-flags");

            // ── 8b. MASTG/MSTG static vulnerability scan ──────────────────────
            try {
                int vulnCount = new VulnerabilityScanner().scan(store, execName);
                log.info("VulnerabilityScanner found {} finding(s)", vulnCount);
            } catch (Exception e) {
                log.warn("VulnerabilityScanner failed — {}", e.getMessage());
            }

            // ── 9. LLM enrichment (skipped when LLM_PROVIDER=none) ────────────
            if (opts.llmEnabled()) {
                try {
                    LlmProvider llmProvider = LlmProviderFactory.create(opts.llmConfig());
                    if (llmProvider != null) {
                        new LlmEnricher(llmProvider, opts.llmMode(), LlmCache.NOOP, macho.isSwift())
                                .enrich(store, execName);
                    } else {
                        log.warn("llmEnabled=true but LLM_PROVIDER=none — skipping enrichment");
                    }
                } catch (Exception e) {
                    log.warn("LLM enrichment skipped — {}", e.getMessage());
                }
            }

        } // store.close() called here

        // ── 10. write scan metadata ───────────────────────────────────────────
        saveScanJson(opts.outputDir().resolve("scan.json"), scanId, info, macho, opts, dbPath, provision);

        long dt = System.currentTimeMillis() - t0;
        log.info("scan={} done in {}ms  db={}", scanId, dt, dbPath);
        return new AnalysisResult(scanId, opts.outputDir(), dt, dbPath);
    }

    // ── helpers ───────────────────────────────────────────────────────────────

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

    private void saveScanJson(Path target, String scanId, InfoPlist info,
                               Macho macho, AnalyzeOptions opts, Path dbPath,
                               MobileProvision.ProvisionInfo provision) {
        try {
            var meta = new java.util.LinkedHashMap<String, Object>();
            meta.put("scanId",             scanId);
            meta.put("bundleExecutable",   info.getExecutableName());
            meta.put("bundleIdentifier",   info.getBundleIdentifier());
            meta.put("isSwift",            macho.isSwift());
            meta.put("isUniversal",        macho.isUniversalBinary());
            meta.put("architectures",      macho.getArchitectureStrings());
            meta.put("dbPath",             dbPath.toString());
            meta.put("ipaPath",            opts.ipaPath().toString());
            if (provision != null) {
                meta.put("bundleTeamId",          provision.teamId());
                meta.put("provisioningProfile",   provision.profileName());
                meta.put("provisioningExpiry",    provision.expiryDate());
            }
            String json = new GsonBuilder().setPrettyPrinting().create().toJson(meta);
            Files.writeString(target, json);
            log.info("Scan metadata written to {}", target);
        } catch (Exception e) {
            log.warn("Could not write scan.json", e);
        }
    }
}
