package io.github.rezabakhshi.embedra.formats.esp;

import java.util.Objects;

/** Side-effect-free structural detector for ESP application images. */
public final class EspImageDetector {
    static final int MAGIC = 0xe9;

    static final int HEADER_LENGTH = 24;

    static final int MAX_SEGMENTS = 16;

    private EspImageDetector() {
    }

    public static EspImageDetection detect(byte[] input) {
        Objects.requireNonNull(input, "input");
        if (input.length == 0 || Byte.toUnsignedInt(input[0]) != MAGIC) {
            return EspImageDetection.NO_MATCH;
        }
        if (input.length < HEADER_LENGTH) {
            return EspImageDetection.MALFORMED;
        }
        int segmentCount = Byte.toUnsignedInt(input[1]);
        int digestFlag = Byte.toUnsignedInt(input[23]);
        if (segmentCount == 0 || segmentCount > MAX_SEGMENTS || digestFlag > 1) {
            return EspImageDetection.MALFORMED;
        }
        return EspImageDetection.MATCH;
    }
}
