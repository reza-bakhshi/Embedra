package io.github.rezabakhshi.embedra.formats.rp.uf2;

import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;

/**
 * Reconstructed contiguous memory segment from validated UF2 blocks.
 */
public record RpUf2Segment(
        long targetAddress,
        byte[] data,
        Optional<RpUf2Family> family) {

    public RpUf2Segment {
        Objects.requireNonNull(data, "data must not be null");
        Objects.requireNonNull(family, "family must not be null");
        data = Arrays.copyOf(data, data.length);
    }

    @Override
    public byte[] data() {
        return Arrays.copyOf(data, data.length);
    }

    public int length() {
        return data.length;
    }

    public long endAddress() {
        return targetAddress + data.length;
    }

    public boolean contains(long address) {
        return address >= targetAddress && address < endAddress();
    }

    public long readU32Le(int offset) {
        if (offset < 0 || offset + 4 > data.length) {
            throw new IndexOutOfBoundsException("Offset " + offset + " + 4 exceeds segment length " + data.length);
        }
        return ((long) (data[offset] & 0xFF))
                | ((long) (data[offset + 1] & 0xFF) << 8)
                | ((long) (data[offset + 2] & 0xFF) << 16)
                | ((long) (data[offset + 3] & 0xFF) << 24);
    }

    public int readU16Le(int offset) {
        if (offset < 0 || offset + 2 > data.length) {
            throw new IndexOutOfBoundsException("Offset " + offset + " + 2 exceeds segment length " + data.length);
        }
        return (data[offset] & 0xFF) | ((data[offset + 1] & 0xFF) << 8);
    }
}
