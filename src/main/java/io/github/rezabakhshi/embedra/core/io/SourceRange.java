package io.github.rezabakhshi.embedra.core.io;

/** A checked half-open byte range in the original input. */
public record SourceRange(long offset, long length) {
    public SourceRange {
        if (offset < 0) {
            throw new IllegalArgumentException("Source offset must be non-negative");
        }
        if (length < 0) {
            throw new IllegalArgumentException("Source length must be non-negative");
        }
        Math.addExact(offset, length);
    }

    public long endExclusive() {
        return offset + length;
    }

    public boolean contains(long position) {
        return position >= offset && position < endExclusive();
    }

    public boolean contains(SourceRange other) {
        return other.offset >= offset && other.endExclusive() <= endExclusive();
    }

    public SourceRange subrange(long relativeOffset, long subrangeLength) {
        if (relativeOffset < 0) {
            throw new IllegalArgumentException("Relative offset must be non-negative");
        }
        SourceRange candidate = new SourceRange(Math.addExact(offset, relativeOffset), subrangeLength);
        if (!contains(candidate)) {
            throw new IllegalArgumentException("Subrange exceeds its parent source range");
        }
        return candidate;
    }
}
