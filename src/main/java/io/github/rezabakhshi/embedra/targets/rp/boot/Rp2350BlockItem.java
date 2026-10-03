package io.github.rezabakhshi.embedra.targets.rp.boot;

import java.util.Arrays;
import java.util.Objects;

/**
 * An individual metadata item parsed from an RP2350 IMAGE_DEF block.
 */
public record Rp2350BlockItem(
        int tag,
        long rawHeaderWord,
        long[] dataWords) {

    public static final int TAG_IMAGE_TYPE = 0x42;

    public static final int TAG_VECTOR_TABLE_OR_ENTRY = 0x43;

    public static final int TAG_BLOCK_SIZE = 0x44;

    public static final int TAG_LAST = 0xFF;

    public Rp2350BlockItem {
        Objects.requireNonNull(dataWords, "dataWords must not be null");
        dataWords = Arrays.copyOf(dataWords, dataWords.length);
    }

    @Override
    public long[] dataWords() {
        return Arrays.copyOf(dataWords, dataWords.length);
    }
}
