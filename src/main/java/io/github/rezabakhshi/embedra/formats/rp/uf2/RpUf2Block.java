package io.github.rezabakhshi.embedra.formats.rp.uf2;

import java.util.Arrays;
import java.util.Objects;

/**
 * An individual 512-byte block from a UF2 container file.
 */
public record RpUf2Block(
        long magicStart0,
        long magicStart1,
        int flags,
        long targetAddress,
        int payloadSize,
        int blockNumber,
        int totalBlocks,
        long familyId,
        byte[] payload,
        long magicEnd) {

    public static final int BLOCK_SIZE = 512;

    public static final long EXPECTED_MAGIC_START0 = 0x0A324655L;

    public static final long EXPECTED_MAGIC_START1 = 0x9E5D5157L;

    public static final long EXPECTED_MAGIC_END = 0x0AB16F30L;

    public static final int FLAG_FAMILY_ID_PRESENT = 0x00002000;

    public RpUf2Block {
        Objects.requireNonNull(payload, "payload must not be null");
        payload = Arrays.copyOf(payload, payload.length);
        if (payload.length != payloadSize) {
            throw new IllegalArgumentException("Payload byte array length must match payloadSize");
        }
    }

    @Override
    public byte[] payload() {
        return Arrays.copyOf(payload, payload.length);
    }

    public boolean hasFamilyId() {
        return (flags & FLAG_FAMILY_ID_PRESENT) != 0;
    }
}
