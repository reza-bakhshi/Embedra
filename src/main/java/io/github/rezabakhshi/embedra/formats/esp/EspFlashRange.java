package io.github.rezabakhshi.embedra.formats.esp;

import java.util.Objects;

/** Checked half-open physical flash range, distinct from a CPU address range. */
public record EspFlashRange(long offset, long length) {
    public EspFlashRange {
        if (offset < 0 || length < 0) {
            throw new IllegalArgumentException("Flash offset and length must be non-negative");
        }
        Math.addExact(offset, length);
    }

    public long endExclusive() {
        return offset + length;
    }

    public boolean overlaps(EspFlashRange other) {
        Objects.requireNonNull(other, "other");
        return offset < other.endExclusive() && other.offset < endExclusive();
    }
}
