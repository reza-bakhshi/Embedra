package io.github.rezabakhshi.embedra.formats.esp;

import io.github.rezabakhshi.embedra.core.io.AddressRange;
import io.github.rezabakhshi.embedra.core.io.SourceRange;
import java.util.Objects;

/** Immutable ESP image segment retaining encoded target and source ranges. */
public final class EspImageSegment {
    private final int index;

    private final long loadAddress;

    private final byte[] data;

    private final SourceRange headerSourceRange;

    private final SourceRange dataSourceRange;

    public EspImageSegment(int index, long loadAddress, byte[] data,
            SourceRange headerSourceRange, SourceRange dataSourceRange) {
        if (index < 0) {
            throw new IllegalArgumentException("Segment index must be non-negative");
        }
        this.index = index;
        this.loadAddress = loadAddress;
        this.data = Objects.requireNonNull(data, "data").clone();
        this.headerSourceRange = Objects.requireNonNull(headerSourceRange,
            "headerSourceRange");
        this.dataSourceRange = Objects.requireNonNull(dataSourceRange, "dataSourceRange");
        if (dataSourceRange.length() != data.length) {
            throw new IllegalArgumentException("Segment data and source lengths differ");
        }
    }

    public int index() {
        return index;
    }

    public long loadAddress() {
        return loadAddress;
    }

    public long length() {
        return data.length;
    }

    public byte[] data() {
        return data.clone();
    }

    public SourceRange headerSourceRange() {
        return headerSourceRange;
    }

    public SourceRange dataSourceRange() {
        return dataSourceRange;
    }

    public AddressRange targetRange() {
        return new AddressRange("default", loadAddress, data.length);
    }
}
