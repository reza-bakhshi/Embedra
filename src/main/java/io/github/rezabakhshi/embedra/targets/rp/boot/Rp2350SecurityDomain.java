package io.github.rezabakhshi.embedra.targets.rp.boot;

/**
 * TrustZone security attribution domain for RP2350 ARM images.
 */
public enum Rp2350SecurityDomain {
    SECURE("Secure"),
    NON_SECURE("Non-Secure");

    private final String description;

    Rp2350SecurityDomain(String description) {
        this.description = description;
    }

    public String description() {
        return description;
    }
}
