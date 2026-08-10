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
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
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
            ApkMeta meta = apk.getApkMeta();
            String xml = apk.getManifestXml();
            return fromMetaAndXml(meta, xml);
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
