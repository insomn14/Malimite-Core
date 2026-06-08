package io.mailmite.core;

import com.dd.plist.NSDictionary;
import com.dd.plist.NSObject;
import com.dd.plist.PropertyListParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Parses an iOS/macOS Info.plist (binary or XML) from a filesystem path.
 * Port of Malimite's InfoPlist.java — Swing tree dependencies removed.
 */
public class InfoPlist {

    private static final Logger log = LoggerFactory.getLogger(InfoPlist.class);

    private final String executableName;
    private final String bundleIdentifier;

    private InfoPlist(String executableName, String bundleIdentifier) {
        this.executableName  = executableName;
        this.bundleIdentifier = bundleIdentifier;
    }

    /** Parse Info.plist at the given path. Handles both binary and XML formats. */
    public static InfoPlist parse(Path plistPath) throws Exception {
        byte[]   data  = Files.readAllBytes(plistPath);
        NSObject plist = PropertyListParser.parse(data);

        String execName = "";
        String bundleId = "";

        if (plist instanceof NSDictionary dict) {
            NSObject exec = dict.objectForKey("CFBundleExecutable");
            NSObject id_  = dict.objectForKey("CFBundleIdentifier");
            if (exec != null) execName = exec.toString();
            if (id_  != null) bundleId = id_.toString();
        }

        log.info("Parsed Info.plist: executable={} bundleId={}", execName, bundleId);
        return new InfoPlist(execName, bundleId);
    }

    public String getExecutableName()  { return executableName; }
    public String getBundleIdentifier() { return bundleIdentifier; }
}
