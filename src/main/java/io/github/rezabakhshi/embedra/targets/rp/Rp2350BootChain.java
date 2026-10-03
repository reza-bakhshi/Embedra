package io.github.rezabakhshi.embedra.targets.rp;

import io.github.rezabakhshi.embedra.targets.rp.boot.Rp2350Architecture;
import io.github.rezabakhshi.embedra.targets.rp.boot.Rp2350BootMetadata;
import io.github.rezabakhshi.embedra.targets.rp.boot.Rp2350SecurityDomain;
import java.util.Objects;
import java.util.Optional;

/**
 * Pure model of the RP2350 multi-stage boot chain from BootROM to application execution.
 */
public final class Rp2350BootChain {

    public enum BootStage {
        BOOT_ROM,
        IMAGE_DEF_VALIDATION,
        OTP_SECURITY_CHECK,
        VECTOR_TABLE_HANDOFF,
        APPLICATION_EXECUTION
    }

    private final Rp2350BootMetadata metadata;

    public Rp2350BootChain(Rp2350BootMetadata metadata) {
        this.metadata = Objects.requireNonNull(metadata, "metadata must not be null");
    }

    public Rp2350BootMetadata metadata() {
        return metadata;
    }

    public Rp2350Architecture targetArchitecture() {
        return metadata.architecture();
    }

    public Rp2350SecurityDomain securityDomain() {
        return metadata.securityDomain();
    }

    public boolean isTrustZoneSecure() {
        return metadata.securityDomain() == Rp2350SecurityDomain.SECURE;
    }

    public Optional<Long> vectorTableAddress() {
        return metadata.vectorTableAddress().isPresent()
                ? Optional.of(metadata.vectorTableAddress().getAsLong())
                : Optional.empty();
    }

    public long executionEntryPoint() {
        return metadata.entryPoint();
    }
}
