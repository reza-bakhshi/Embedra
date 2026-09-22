package io.github.rezabakhshi.embedra.formats.esp;

import io.github.rezabakhshi.embedra.core.io.SourceRange;
import java.util.Objects;
import java.util.Optional;

/** Immutable checksum, alignment padding, and optional appended digest. */
public final class EspImageFooter {
    private final byte[] padding;

    private final SourceRange paddingSourceRange;

    private final int storedChecksum;

    private final int calculatedChecksum;

    private final SourceRange checksumSourceRange;

    private final byte[] storedDigest;

    private final byte[] calculatedDigest;

    private final SourceRange digestSourceRange;

    public EspImageFooter(byte[] padding, SourceRange paddingSourceRange, int storedChecksum,
            int calculatedChecksum, SourceRange checksumSourceRange, byte[] storedDigest,
            byte[] calculatedDigest, SourceRange digestSourceRange) {
        this.padding = Objects.requireNonNull(padding, "padding").clone();
        this.paddingSourceRange = Objects.requireNonNull(paddingSourceRange,
            "paddingSourceRange");
        this.storedChecksum = storedChecksum;
        this.calculatedChecksum = calculatedChecksum;
        this.checksumSourceRange = Objects.requireNonNull(checksumSourceRange,
            "checksumSourceRange");
        this.storedDigest = Objects.requireNonNull(storedDigest, "storedDigest").clone();
        this.calculatedDigest = Objects.requireNonNull(calculatedDigest,
            "calculatedDigest").clone();
        this.digestSourceRange = digestSourceRange;
        if (paddingSourceRange.length() != padding.length
            || storedDigest.length != calculatedDigest.length
            || (digestSourceRange == null) != (storedDigest.length == 0)) {
            throw new IllegalArgumentException("Inconsistent ESP image footer model");
        }
    }

    public byte[] padding() {
        return padding.clone();
    }

    public SourceRange paddingSourceRange() {
        return paddingSourceRange;
    }

    public int storedChecksum() {
        return storedChecksum;
    }

    public int calculatedChecksum() {
        return calculatedChecksum;
    }

    public boolean checksumValid() {
        return storedChecksum == calculatedChecksum;
    }

    public SourceRange checksumSourceRange() {
        return checksumSourceRange;
    }

    public boolean digestPresent() {
        return digestSourceRange != null;
    }

    public byte[] storedDigest() {
        return storedDigest.clone();
    }

    public byte[] calculatedDigest() {
        return calculatedDigest.clone();
    }

    public boolean digestValid() {
        return digestPresent() && java.util.Arrays.equals(storedDigest, calculatedDigest);
    }

    public Optional<SourceRange> digestSourceRange() {
        return Optional.ofNullable(digestSourceRange);
    }
}
