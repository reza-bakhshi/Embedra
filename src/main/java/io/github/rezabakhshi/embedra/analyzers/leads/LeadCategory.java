package io.github.rezabakhshi.embedra.analyzers.leads;

/**
 * High-level category classification for discovered security and CTF leads (AN-005).
 *
 * <p>Under requirement AN-005, candidate comparisons, hidden commands, debug shells,
 * OTA endpoints, and authorization branches are treated as ranked leads, not facts.</p>
 */
public enum LeadCategory {
    PASSWORD_TOKEN_COMPARISON("Password / Token Comparison", "Candidate credential, token, PIN, or hash comparison"),
    DEBUG_COMMAND("Debug / Hidden Command", "Candidate hidden, administrative, or diagnostic CLI command"),
    DEBUG_SHELL("Debug Shell / Console", "Candidate interactive debug shell, serial console, or REPL loop"),
    OTA_ENDPOINT("OTA Endpoint", "Candidate over-the-air firmware update endpoint, URL, or handler"),
    AUTHORIZATION_BRANCH("Authorization Branch", "Candidate privilege check or credential outcome branch");

    private final String displayName;

    private final String description;

    LeadCategory(String displayName, String description) {
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
