package io.github.rezabakhshi.embedra.formats.esp8266;

import io.github.rezabakhshi.embedra.core.io.AddressRange;
import io.github.rezabakhshi.embedra.core.io.SourceRange;
import java.util.Objects;

/** ESP8266 segment with an explicit distinction between RAM and flash mapping. */
public final class Esp8266ImageSegment {
    private final int index;

    private final long encodedLoadAddress;

    private final byte[] data;

    private final boolean flashMapped;

    private final SourceRange headerSourceRange;

    private final SourceRange dataSourceRange;

    public Esp8266ImageSegment(int index, long encodedLoadAddress, byte[] data,
            boolean flashMapped, SourceRange headerSourceRange,
            SourceRange dataSourceRange) {
        if (index < 0) {
            throw new IllegalArgumentException("Segment index must be non-negative");
        }
        this.index = index;
        this.encodedLoadAddress = encodedLoadAddress;
        this.data = Objects.requireNonNull(data, "data").clone();
        this.flashMapped = flashMapped;
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

    public long encodedLoadAddress() {
        return encodedLoadAddress;
    }

    public long length() {
        return data.length;
    }

    public byte[] data() {
        return data.clone();
    }

    public boolean flashMapped() {
        return flashMapped;
    }

    public SourceRange headerSourceRange() {
        return headerSourceRange;
    }

    public SourceRange dataSourceRange() {
        return dataSourceRange;
    }

    public AddressRange directTargetRange() {
        if (flashMapped) {
            throw new IllegalStateException("Flash-mapped segment requires a flash base");
        }
        return new AddressRange("default", encodedLoadAddress, data.length);
    }

    public long resolveLoadAddress(long flashBase) {
        if (!flashMapped) {
            return encodedLoadAddress;
        }
        if (flashBase < 0 || flashBase > 0x000f_fff0L || (flashBase & 0xfff) != 0) {
            throw new IllegalArgumentException(
                "ESP8266 version 2 flash base must be 4 KiB aligned and within IROM");
        }
        return 0x4020_0000L + flashBase + dataSourceRange.offset();
    }
}
