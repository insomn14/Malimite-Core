package io.malimite.core;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/** Cheap pre-flight checks so we don't waste a JADX spawn on garbage. */
public final class ApkValidator {

    private ApkValidator() {}

    public static void validate(Path apk) throws IOException {
        if (!Files.exists(apk)) throw new IOException("APK not found: " + apk);
        if (Files.size(apk) < 64) throw new IOException("APK suspiciously small");

        try (ZipFile zf = new ZipFile(apk.toFile())) {
            boolean hasManifest = false;
            boolean hasDex = false;
            var it = zf.stream().iterator();
            while (it.hasNext()) {
                ZipEntry e = it.next();
                String n = e.getName();
                if ("AndroidManifest.xml".equals(n)) hasManifest = true;
                String base = n.contains("/") ? n.substring(n.lastIndexOf('/') + 1) : n;
                if (base.toLowerCase(Locale.ROOT).matches("classes\\d*\\.dex")) hasDex = true;
            }
            if (!hasManifest)
                throw new IOException("Not an APK: missing AndroidManifest.xml");
            if (!hasDex)
                throw new IOException("Not an APK: missing classes.dex");
        }
    }
}
