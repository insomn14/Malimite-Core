package io.malimite.core;

import net.dongliu.apk.parser.ApkFile;
import net.dongliu.apk.parser.bean.ApkMeta;
import net.dongliu.apk.parser.bean.UseFeature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilderFactory;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.Locale;

/**
 * Parses AndroidManifest metadata from an APK (binary AXML via apk-parser).
 */
public final class AndroidManifestParser {

    private static final Logger log = LoggerFactory.getLogger(AndroidManifestParser.class);

    private AndroidManifestParser() {}

    public record ExportedComponent(String type, String name, boolean exported, String permission) {}

    public record DeepLink(String component, String scheme, String host, String pathPrefix) {}

    public record ManifestInfo(
            String packageName,
            String versionName,
            Long versionCode,
            Integer minSdk,
            Integer targetSdk,
            boolean debuggable,
            Boolean allowBackup,
            Boolean usesCleartextTraffic,
            String networkSecurityConfig,
            List<String> permissions,
            List<ExportedComponent> components,
            List<DeepLink> deepLinks
    ) {
        public String applicationId() {
            return packageName != null ? packageName : "unknown";
        }
    }

    /** Parse from the original APK path (preferred — apk-parser reads binary AXML). */
    public static ManifestInfo parse(Path apkPath) throws Exception {
        try (ApkFile apk = new ApkFile(apkPath.toFile())) {
            ApkMeta meta = null;
            String xml = null;
            Exception err = null;
            try {
                meta = apk.getApkMeta();
            } catch (Exception e) {
                err = e;
                log.warn("apk-parser getApkMeta failed ({}); falling back to manifest XML / aapt2", e.getMessage());
            }
            try {
                xml = apk.getManifestXml();
            } catch (Exception e) {
                if (err == null) err = e;
                log.warn("apk-parser getManifestXml failed: {}", e.getMessage());
            }
            if (xml == null || xml.isBlank()) {
                // net.dongliu:apk-parser 2.6.10 chokes on some resource tables
                // ("java.lang.IllegalArgumentException: newPosition > limit").
                // Fall back to aapt2 (bundled with dAsstLLM), which is robust.
                log.warn("apk-parser manifest unavailable ({}); using aapt2 dump badging",
                        err != null ? err.getMessage() : "n/a");
                return parseViaAapt2(apkPath);
            }
            return fromMetaAndXml(meta, xml);
        }
    }

    private static String exec(String... argv) throws Exception {
        ProcessBuilder pb = new ProcessBuilder(argv);
        pb.redirectErrorStream(true);
        Process p = pb.start();
        StringBuilder sb = new StringBuilder();
        try (BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = br.readLine()) != null) sb.append(line).append('\n');
        }
        int code = p.waitFor();
        if (code != 0) throw new IllegalStateException("command failed (" + code + "): " + argv[0]);
        return sb.toString();
    }

    /** Minimal manifest info via `aapt2 dump badging` when apk-parser cannot read the APK. */
    private static ManifestInfo parseViaAapt2(Path apkPath) {
        try {
            String badging = exec("aapt2", "dump", "badging", apkPath.toString());
            String pkg = match(badging, "package: name='([^']+)'");
            String versionName = match(badging, "versionName='([^']+)'");
            String versionCode = match(badging, "versionCode='([^']+)'");
            Integer minSdk = parseIntOrNull(match(badging, "sdkVersion:'([^']+)'"));
            Integer targetSdk = parseIntOrNull(match(badging, "targetSdkVersion:'([^']+)'"));
            boolean debuggable = badging.contains("application-debuggable");
            List<String> perms = new ArrayList<>();
            Matcher pm = Pattern.compile("(?m)^uses-permission: name='([^']+)'").matcher(badging);
            while (pm.find()) perms.add(pm.group(1));
            log.info("Manifest (aapt2): package={} minSdk={} targetSdk={} perms={}",
                    pkg, minSdk, targetSdk, perms.size());
            return new ManifestInfo(
                    pkg, versionName, parseLongOrNull(versionCode), minSdk, targetSdk,
                    debuggable, null, null, null,
                    List.copyOf(perms), new ArrayList<>(), new ArrayList<>());
        } catch (Exception e) {
            log.warn("aapt2 fallback failed: {}", e.getMessage());
            return new ManifestInfo(
                    null, null, null, null, null,
                    false, null, null, null, List.of(), new ArrayList<>(), new ArrayList<>());
        }
    }

    private static String match(String text, String re) {
        Matcher m = Pattern.compile(re).matcher(text);
        return m.find() ? m.group(1) : null;
    }

    private static Long parseLongOrNull(String s) {
        if (s == null) return null;
        try {
            return Long.parseLong(s);
        } catch (NumberFormatException e) {
            try { return Long.parseLong(s.replaceAll("[^0-9]", "")); } catch (NumberFormatException e2) { return null; }
        }
    }

    static ManifestInfo fromMetaAndXml(ApkMeta meta, String manifestXml) throws Exception {
        String packageName = meta != null ? meta.getPackageName() : null;
        String versionName = meta != null ? meta.getVersionName() : null;
        Long versionCode = meta != null ? meta.getVersionCode() : null;
        Integer minSdk = parseIntOrNull(meta != null ? meta.getMinSdkVersion() : null);
        Integer targetSdk = parseIntOrNull(meta != null ? meta.getTargetSdkVersion() : null);

        List<String> permissions = new ArrayList<>();
        if (meta != null && meta.getUsesPermissions() != null)
            permissions.addAll(meta.getUsesPermissions());

        boolean debuggable = false;
        Boolean allowBackup = null;
        Boolean usesCleartext = null;
        String nsc = null;
        List<ExportedComponent> components = new ArrayList<>();
        List<DeepLink> deepLinks = new ArrayList<>();

        if (manifestXml != null && !manifestXml.isBlank()) {
            Document doc = DocumentBuilderFactory.newInstance()
                    .newDocumentBuilder()
                    .parse(new ByteArrayInputStream(manifestXml.getBytes(StandardCharsets.UTF_8)));
            // When apk-parser's Resources step failed (getApkMeta threw) meta is
            // null; recover the identity fields that live in the AXML itself.
            if (packageName == null) {
                String p = doc.getDocumentElement().getAttribute("package");
                if (p != null && !p.isBlank()) packageName = p;
            }
            if (versionName == null) versionName = attr(doc.getDocumentElement(), "versionName");
            if (versionCode == null) {
                String vc = attr(doc.getDocumentElement(), "versionCode");
                if (vc != null) versionCode = parseLongOrNull(vc);
            }
            NodeList sdk = doc.getElementsByTagName("uses-sdk");
            if (minSdk == null && sdk.getLength() > 0 && sdk.item(0) instanceof Element sdkEl) {
                minSdk = parseIntOrNull(attr(sdkEl, "minSdkVersion"));
            }
            if (targetSdk == null && sdk.getLength() > 0 && sdk.item(0) instanceof Element sdkEl) {
                targetSdk = parseIntOrNull(attr(sdkEl, "targetSdkVersion"));
            }
            Element app = firstChildElement(doc.getDocumentElement(), "application");
            if (app != null) {
                debuggable = boolAttr(app, "debuggable", false);
                if (app.hasAttribute("android:allowBackup") || app.hasAttribute("allowBackup"))
                    allowBackup = boolAttr(app, "allowBackup", true);
                if (app.hasAttribute("android:usesCleartextTraffic") || app.hasAttribute("usesCleartextTraffic"))
                    usesCleartext = boolAttr(app, "usesCleartextTraffic", false);
                nsc = attr(app, "networkSecurityConfig");
                collectComponents(app, "activity", components, deepLinks);
                collectComponents(app, "activity-alias", components, deepLinks);
                collectComponents(app, "service", components, deepLinks);
                collectComponents(app, "receiver", components, deepLinks);
                collectComponents(app, "provider", components, deepLinks);
            }
            if (permissions.isEmpty()) {
                NodeList uses = doc.getElementsByTagName("uses-permission");
                for (int i = 0; i < uses.getLength(); i++) {
                    if (uses.item(i) instanceof Element el) {
                        String name = attr(el, "name");
                        if (name != null) permissions.add(name);
                    }
                }
            }
        }

        if (meta != null && meta.getUsesFeatures() != null) {
            for (UseFeature f : meta.getUsesFeatures()) {
                log.debug("uses-feature: {}", f.getName());
            }
        }

        log.info("Manifest: package={} minSdk={} targetSdk={} perms={} components={} deepLinks={}",
                packageName, minSdk, targetSdk, permissions.size(), components.size(), deepLinks.size());
        return new ManifestInfo(
                packageName, versionName, versionCode, minSdk, targetSdk,
                debuggable, allowBackup, usesCleartext, nsc,
                List.copyOf(permissions), List.copyOf(components), List.copyOf(deepLinks));
    }

    private static void collectComponents(Element app, String tag,
                                          List<ExportedComponent> out,
                                          List<DeepLink> deepLinks) {
        NodeList nodes = app.getElementsByTagName(tag);
        for (int i = 0; i < nodes.getLength(); i++) {
            if (!(nodes.item(i) instanceof Element el)) continue;
            if (el.getParentNode() != app) continue;
            String name = attr(el, "name");
            if (name == null || name.isBlank()) continue;
            boolean hasIntentFilter = el.getElementsByTagName("intent-filter").getLength() > 0;
            boolean exported;
            if (el.hasAttribute("android:exported") || el.hasAttribute("exported")) {
                exported = boolAttr(el, "exported", false);
            } else {
                exported = hasIntentFilter;
            }
            String perm = attr(el, "permission");
            out.add(new ExportedComponent(tag, name, exported, perm));

            NodeList filters = el.getElementsByTagName("intent-filter");
            for (int f = 0; f < filters.getLength(); f++) {
                if (!(filters.item(f) instanceof Element filter)) continue;
                NodeList datas = filter.getElementsByTagName("data");
                for (int d = 0; d < datas.getLength(); d++) {
                    if (!(datas.item(d) instanceof Element data)) continue;
                    String scheme = attr(data, "scheme");
                    String host = attr(data, "host");
                    String path = attr(data, "pathPrefix");
                    if (path == null) path = attr(data, "path");
                    if (path == null) path = attr(data, "pathPattern");
                    if (scheme != null || host != null)
                        deepLinks.add(new DeepLink(name, scheme, host, path));
                }
            }
        }
    }

    private static Element firstChildElement(Element parent, String tag) {
        NodeList nodes = parent.getElementsByTagName(tag);
        for (int i = 0; i < nodes.getLength(); i++) {
            if (nodes.item(i) instanceof Element el && el.getParentNode() == parent)
                return el;
        }
        return null;
    }

    private static String attr(Element el, String local) {
        if (el.hasAttribute("android:" + local)) return el.getAttribute("android:" + local);
        if (el.hasAttribute(local)) return el.getAttribute(local);
        return null;
    }

    private static boolean boolAttr(Element el, String local, boolean def) {
        String v = attr(el, local);
        if (v == null) return def;
        return "true".equalsIgnoreCase(v) || "1".equals(v);
    }

    private static Integer parseIntOrNull(String s) {
        if (s == null || s.isBlank()) return null;
        try {
            return Integer.parseInt(s.trim());
        } catch (NumberFormatException e) {
            return switch (s.trim().toLowerCase(Locale.ROOT)) {
                case "p", "pie" -> 28;
                case "q" -> 29;
                case "r" -> 30;
                case "s" -> 31;
                case "t" -> 33;
                case "u" -> 34;
                default -> null;
            };
        }
    }
}
