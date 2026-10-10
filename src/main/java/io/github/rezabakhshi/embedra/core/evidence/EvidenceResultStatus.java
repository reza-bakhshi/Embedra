package io.github.rezabakhshi.embedra.core.evidence;

/**
 * Result status for verification evidence records.
 */
public enum EvidenceResultStatus {
    PASS,
    FAIL,
    SKIPPED;

    public static EvidenceResultStatus parse(String value) {
        if (value == null) {
            throw new IllegalArgumentException("Evidence result status must not be null");
        }
        return valueOf(value.trim().toUpperCase());
    }
}
