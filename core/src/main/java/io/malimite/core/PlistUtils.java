package io.malimite.core;

import com.dd.plist.NSObject;
import com.dd.plist.PropertyListParser;
import com.google.gson.GsonBuilder;

import java.util.Arrays;

/** Utility methods for detecting and decoding binary/XML plists. */
public final class PlistUtils {

    private PlistUtils() {}

    public static boolean isBinaryPlist(byte[] bytes) {
        if (bytes.length < 6) return false;
        return "bplist".equals(new String(Arrays.copyOf(bytes, 6)));
    }

    /** Decodes a binary plist to a pretty-printed JSON string. */
    public static String decodeBinaryPropertyList(byte[] plistData) {
        try {
            NSObject plist = PropertyListParser.parse(plistData);
            return new GsonBuilder().setPrettyPrinting().create().toJson(plist.toJavaObject());
        } catch (Exception e) {
            return null;
        }
    }
}
