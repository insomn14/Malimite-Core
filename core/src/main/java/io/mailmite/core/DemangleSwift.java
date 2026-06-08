package io.mailmite.core;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Decodes Swift name-mangled symbols (prefix {@code _$s}) to class/method pairs. */
public final class DemangleSwift {

    private static final Logger log = LoggerFactory.getLogger(DemangleSwift.class);

    private DemangleSwift() {}

    public record DemangledName(String className, String fullMethodName) {}

    public static DemangledName demangleSwiftName(String mangledName) {
        if (mangledName == null || !mangledName.startsWith("_$s")) return null;

        try {
            String remaining = mangledName.substring(3);

            int classLen = extractNumber(remaining);
            String className = remaining.substring(
                    String.valueOf(classLen).length(),
                    String.valueOf(classLen).length() + classLen);

            remaining = remaining.substring(String.valueOf(classLen).length() + classLen);

            StringBuilder methodBuilder = new StringBuilder();
            while (!remaining.isEmpty()) {
                int idx = findNextNumberIndex(remaining);
                if (idx == -1) break;

                String afterNum = remaining.substring(idx);
                int len = extractNumber(afterNum);
                int numLen = String.valueOf(len).length();
                methodBuilder.append(afterNum, numLen, numLen + len);
                remaining = afterNum.substring(numLen + len);
            }

            return new DemangledName(className, methodBuilder.toString());
        } catch (Exception e) {
            log.debug("Failed to demangle Swift symbol: {}", mangledName);
        }
        return null;
    }

    private static int findNextNumberIndex(String s) {
        for (int i = 0; i < s.length(); i++) {
            if (Character.isDigit(s.charAt(i)) && s.charAt(i) != '0') return i;
        }
        return -1;
    }

    private static int extractNumber(String s) {
        StringBuilder sb = new StringBuilder();
        boolean started = false;
        for (char c : s.toCharArray()) {
            if (Character.isDigit(c)) {
                if (c != '0' || started) { sb.append(c); started = true; }
            } else break;
        }
        return sb.length() > 0 ? Integer.parseInt(sb.toString()) : 0;
    }
}
