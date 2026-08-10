package io.malimite.core;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/** Mobile package platform for analyzer routing and rule gating. */
public enum PackagePlatform {
    IOS,
    ANDROID;

    /**
     * Detect platform from file extension, then ZIP contents as a fallback.
     */
    public static PackagePlatform detect(Path packagePath) throws IOException {
        String name = packagePath.getFileName().toString().toLowerCase(Locale.ROOT);
        if (name.endsWith(".apk")) return ANDROID;
        if (name.endsWith(".ipa")) return IOS;

        if (!Files.exists(packagePath) || Files.size(packagePath) < 4) {
            throw new IOException("Unknown package type: " + packagePath);
        }

        try (ZipFile zf = new ZipFile(packagePath.toFile())) {
            boolean hasManifest = false;
            boolean hasDex = false;
            boolean hasPayloadApp = false;
            var it = zf.stream().iterator();
            while (it.hasNext()) {
                ZipEntry e = it.next();
                String n = e.getName();
                if ("AndroidManifest.xml".equals(n) || n.endsWith("/AndroidManifest.xml"))
                    hasManifest = true;
                if (n.matches("classes(\\d*)\\.dex") || n.endsWith("/classes.dex"))
                    hasDex = true;
                if (n.startsWith("Payload/") && n.contains(".app/"))
                    hasPayloadApp = true;
            }
            if (hasManifest && hasDex) return ANDROID;
            if (hasPayloadApp) return IOS;
        }
        throw new IOException("Cannot detect package platform (expected .ipa or .apk): " + packagePath);
    }

    public boolean matchesRule(VulnerabilityRule.Platform rulePlatform) {
        return rulePlatform == VulnerabilityRule.Platform.BOTH
                || (this == IOS && rulePlatform == VulnerabilityRule.Platform.IOS)
                || (this == ANDROID && rulePlatform == VulnerabilityRule.Platform.ANDROID);
    }
}
