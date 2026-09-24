package io.github.rezabakhshi.embedra.analyzers.esp;

import io.github.rezabakhshi.embedra.pack.RedistributionStatus;
import java.util.Objects;

/** Audited license disposition for one component linked into a Function ID reference build. */
public record Esp32S3FidComponent(String name, String license, RedistributionStatus redistribution) {
    public Esp32S3FidComponent {
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(license, "license");
        Objects.requireNonNull(redistribution, "redistribution");
        if (name.isBlank() || license.isBlank()) {
            throw new IllegalArgumentException("Component audit entries must be non-blank");
        }
    }
}
