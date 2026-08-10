package io.mailmite.core;

/** Outcome of a security-control assessment check. */
public enum AssessmentStatus {
    PRESENT,
    PARTIAL,
    ABSENT,
    UNKNOWN;

    public static AssessmentStatus fromString(String s) {
        if (s == null || s.isBlank()) return UNKNOWN;
        try {
            return valueOf(s.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            return UNKNOWN;
        }
    }
}
