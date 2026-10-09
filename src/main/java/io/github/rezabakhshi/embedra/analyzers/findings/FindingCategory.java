package io.github.rezabakhshi.embedra.analyzers.findings;

/**
 * Top-level classification category for unified findings across all analyzers (AN-006).
 */
public enum FindingCategory {
    CTF_ENTITY("CTF & Firmware Entity", "Discovered endpoints, tokens, credentials, certificates, and flags"),
    CRYPTOGRAPHY("Cryptography", "Cryptographic constants, algorithms, keys, and entropy anomalies"),
    LOGGING_DIAGNOSTIC("Logging & Diagnostics", "Diagnostic logging, assert idioms, and panic recovery call sites"),
    SECURITY_LEAD("Security Lead", "Candidate comparisons, hidden commands, shells, and authorization branches"),
    CUSTOM_PLUGIN("Custom Plugin", "User-defined scanner plugin matches and leads");

    private final String displayName;

    private final String description;

    FindingCategory(String displayName, String description) {
        this.displayName = displayName;
        this.description = description;
    }

    public String displayName() {
        return displayName;
    }

    public String description() {
        return description;
    }
}
