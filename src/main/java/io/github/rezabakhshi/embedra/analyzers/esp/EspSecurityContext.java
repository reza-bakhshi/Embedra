package io.github.rezabakhshi.embedra.analyzers.esp;

import io.github.rezabakhshi.embedra.formats.esp.EspImageFooter;
import io.github.rezabakhshi.embedra.formats.esp.EspPartitionEntry;
import java.util.List;
import java.util.Objects;

/** Immutable image-only inputs for an ESP security summary. */
public final class EspSecurityContext {
    private final EspImageFooter imageFooter;

    private final byte[] signatureRegion;

    private final long signatureRegionOffset;

    private final List<EspPartitionEntry> partitions;

    public EspSecurityContext(EspImageFooter imageFooter, byte[] signatureRegion,
            long signatureRegionOffset, List<EspPartitionEntry> partitions) {
        this.imageFooter = Objects.requireNonNull(imageFooter, "imageFooter");
        this.signatureRegion = Objects.requireNonNull(signatureRegion,
            "signatureRegion").clone();
        this.partitions = List.copyOf(partitions);
        if (signatureRegionOffset < 0) {
            throw new IllegalArgumentException("Signature-region offset must not be negative");
        }
        this.signatureRegionOffset = signatureRegionOffset;
    }

    public EspImageFooter imageFooter() {
        return imageFooter;
    }

    public byte[] signatureRegion() {
        return signatureRegion.clone();
    }

    public long signatureRegionOffset() {
        return signatureRegionOffset;
    }

    public List<EspPartitionEntry> partitions() {
        return partitions;
    }
}
