package io.github.rezabakhshi.embedra.core.fixture;

/**
 * Redistribution policy for test and acceptance fixtures.
 */
public enum RedistributionStatus {
    /** Publicly redistributable fixture safe to commit and package. */
    REDISTRIBUTABLE("REDISTRIBUTABLE"),

    /** Restricted local firmware capture that must remain uncommitted. */
    RESTRICTED_LOCAL("RESTRICTED_LOCAL"),

    /** Sensitive or proprietary private firmware permitted only by sanitized digest. */
    PROPRIETARY_PRIVATE("PROPRIETARY_PRIVATE");

    private final String id;

    RedistributionStatus(String id) {
        this.id = id;
    }

    public String id() {
        return id;
    }

    public boolean isRedistributable() {
        return this == REDISTRIBUTABLE;
    }

    public boolean isPrivate() {
        return this != REDISTRIBUTABLE;
    }

    public static RedistributionStatus parse(String value) {
        if (value == null) {
            throw new IllegalArgumentException("Redistribution status must not be null");
        }
        for (RedistributionStatus status : values()) {
            if (status.id.equalsIgnoreCase(value.trim())) {
                return status;
            }
        }
        throw new IllegalArgumentException("Unknown redistribution status: " + value);
    }
}
