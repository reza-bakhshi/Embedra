package io.github.rezabakhshi.embedra.core.io;

import java.util.Objects;
import java.util.Optional;

/** A checked half-open range in an explicitly named target address space. */
public record AddressRange(String addressSpace, long start, long length) {
    public AddressRange {
        Objects.requireNonNull(addressSpace, "addressSpace");
        if (addressSpace.isBlank()) {
            throw new IllegalArgumentException("Address space must not be blank");
        }
        if (start < 0) {
            throw new IllegalArgumentException("Address start must be non-negative");
        }
        if (length < 0) {
            throw new IllegalArgumentException("Address length must be non-negative");
        }
        Math.addExact(start, length);
    }

    public long endExclusive() {
        return start + length;
    }

    public boolean overlaps(AddressRange other) {
        Objects.requireNonNull(other, "other");
        return addressSpace.equals(other.addressSpace)
            && start < other.endExclusive()
            && other.start < endExclusive();
    }

    public Optional<AddressRange> intersection(AddressRange other) {
        if (!overlaps(other)) {
            return Optional.empty();
        }
        long intersectionStart = Math.max(start, other.start);
        long intersectionEnd = Math.min(endExclusive(), other.endExclusive());
        return Optional.of(new AddressRange(addressSpace, intersectionStart,
            intersectionEnd - intersectionStart));
    }
}
