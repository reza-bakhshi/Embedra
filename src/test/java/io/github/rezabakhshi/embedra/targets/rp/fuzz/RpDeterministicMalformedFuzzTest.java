package io.github.rezabakhshi.embedra.targets.rp.fuzz;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.formats.rp.uf2.RpUf2Block;
import io.github.rezabakhshi.embedra.formats.rp.uf2.RpUf2Family;
import io.github.rezabakhshi.embedra.formats.rp.uf2.RpUf2Parser;
import io.github.rezabakhshi.embedra.targets.rp.boot.Rp2040Boot2Checksum;
import io.github.rezabakhshi.embedra.targets.rp.boot.RpBootMetadataParser;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Random;
import org.junit.jupiter.api.Test;

public class RpDeterministicMalformedFuzzTest {

    private static final long SEED = 0x2040_2350_DEAD_BEEFL;

    @Test
    void testDeterministicMalformedFuzzCampaign() {
        Random rng = new Random(SEED);
        int totalTests = 0;
        int passedClosed = 0;

        // --- 1. UF2 Block Fuzzing (100 mutations) ---
        byte[] validUf2Block = createValidUf2Block(0x10000000L, 0, 1, RpUf2Family.RP2040.familyId());
        for (int i = 0; i < 100; i++) {
            totalTests++;
            byte[] mutated = validUf2Block.clone();
            ByteBuffer buf = ByteBuffer.wrap(mutated).order(ByteOrder.LITTLE_ENDIAN);
            int mutationType = i % 8;

            switch (mutationType) {
                case 0 -> { // Corrupt magicStart0
                    long badMagic = rng.nextInt();
                    if (badMagic == RpUf2Block.EXPECTED_MAGIC_START0) {
                        badMagic++;
                    }
                    buf.putInt(0, (int) badMagic);
                }
                case 1 -> { // Corrupt magicStart1
                    long badMagic = rng.nextInt();
                    if (badMagic == RpUf2Block.EXPECTED_MAGIC_START1) {
                        badMagic++;
                    }
                    buf.putInt(4, (int) badMagic);
                }
                case 2 -> { // Corrupt magicEnd
                    long badMagic = rng.nextInt();
                    if (badMagic == RpUf2Block.EXPECTED_MAGIC_END) {
                        badMagic++;
                    }
                    buf.putInt(508, (int) badMagic);
                }
                case 3 -> { // Truncated block (not multiple of 512)
                    int truncLen = 1 + rng.nextInt(511);
                    byte[] trunc = new byte[truncLen];
                    System.arraycopy(mutated, 0, trunc, 0, truncLen);
                    mutated = trunc;
                }
                case 4 -> { // Invalid payload size (0, negative, or > 476)
                    int badPayloadSize = rng.nextBoolean() ? 0 : (477 + rng.nextInt(1000));
                    buf.putInt(16, badPayloadSize);
                }
                case 5 -> { // Invalid block number (negative or >= numBlocks)
                    int badBlockNo = rng.nextBoolean() ? -1 - rng.nextInt(100) : (1 + rng.nextInt(100));
                    buf.putInt(20, badBlockNo);
                }
                case 6 -> { // Mismatched total blocks
                    buf.putInt(24, 2 + rng.nextInt(10));
                }
                case 7 -> { // Unsupported family ID
                    long badFamily = 0x12340000L | rng.nextInt(0xFFFF);
                    buf.putInt(28, (int) badFamily);
                }
                default -> throw new IllegalStateException();
            }

            final byte[] testInput = mutated;
            DiagnosticException ex = assertThrows(
                    DiagnosticException.class,
                    () -> RpUf2Parser.parse(testInput, ParserLimits.defaults(), CancellationToken.none()),
                    "UF2 mutation " + i + " should fail closed with DiagnosticException");

            DiagnosticCode code = ex.diagnostic().code();
            assertTrue(
                    code == DiagnosticCode.RP_UF2_INVALID
                            || code == DiagnosticCode.RP_UF2_MAGIC_MISMATCH
                            || code == DiagnosticCode.RP_UF2_FAMILY_MISMATCH,
                    "Expected UF2 diagnostic but got: " + code);
            passedClosed++;
        }

        // --- 2. RP2040 Boot2 Fuzzing (100 mutations) ---
        byte[] validBoot2 = createValidRp2040Boot2();
        for (int i = 0; i < 100; i++) {
            totalTests++;
            byte[] mutated = validBoot2.clone();
            ByteBuffer buf = ByteBuffer.wrap(mutated).order(ByteOrder.LITTLE_ENDIAN);
            int mutationType = i % 5;

            switch (mutationType) {
                case 0 -> { // Corrupted CRC (neither correct nor placeholder)
                    long badCrc = rng.nextLong() & 0xFFFFFFFFL;
                    long correctCrc = Rp2040Boot2Checksum.calculate(mutated, 0, 252);
                    if (badCrc == correctCrc || badCrc == Rp2040Boot2Checksum.PLACEHOLDER_CRC2) {
                        badCrc ^= 0xDEADBEEFL;
                    }
                    buf.putInt(252, (int) badCrc);
                }
                case 1 -> { // Mutate data in checksummed region while leaving stored CRC
                    int offset = rng.nextInt(250);
                    mutated[offset] ^= (byte) (1 + rng.nextInt(250));
                }
                case 2 -> { // Truncated boot2 (< 256 bytes)
                    int truncLen = rng.nextInt(255);
                    byte[] trunc = new byte[truncLen];
                    System.arraycopy(mutated, 0, trunc, 0, truncLen);
                    mutated = trunc;
                }
                case 3 -> { // Corrupted initial SP (outside 0x20000000..0x20042000)
                    long badSp = rng.nextBoolean() ? 0x10000000L : 0x30000000L;
                    buf.putInt(256, (int) badSp);
                }
                case 4 -> { // Corrupted Reset Vector (even address, bit 0 == 0)
                    long badReset = 0x10000100L; // even address (bit 0 = 0, invalid Thumb)
                    buf.putInt(260, (int) badReset);
                }
                default -> throw new IllegalStateException();
            }

            final byte[] testInput = mutated;
            DiagnosticException ex = assertThrows(
                    DiagnosticException.class,
                    () -> RpBootMetadataParser.parseRp2040Strict(testInput, 0x10000000L),
                    "RP2040 boot2 mutation " + i + " should fail closed with DiagnosticException");

            DiagnosticCode code = ex.diagnostic().code();
            assertTrue(
                    code == DiagnosticCode.RP_BOOT_CRC_MISMATCH || code == DiagnosticCode.RP_BOOT_METADATA_INVALID,
                    "Expected boot2 diagnostic but got: " + code);
            passedClosed++;
        }

        // --- 3. RP2350 IMAGE_DEF Fuzzing (100 mutations) ---
        byte[] validImageDef = createValidRp2350ImageDef();
        for (int i = 0; i < 100; i++) {
            totalTests++;
            byte[] mutated = validImageDef.clone();
            ByteBuffer buf = ByteBuffer.wrap(mutated).order(ByteOrder.LITTLE_ENDIAN);
            int mutationType = i % 5;

            switch (mutationType) {
                case 0 -> { // Corrupted start magic
                    long badMagic = rng.nextInt();
                    if (badMagic == RpBootMetadataParser.IMAGE_DEF_START_MAGIC) {
                        badMagic++;
                    }
                    buf.putInt(0, (int) badMagic);
                }
                case 1 -> { // Missing or corrupted end marker (replace 0xAB123579)
                    long badEnd = rng.nextInt();
                    if (badEnd == RpBootMetadataParser.IMAGE_DEF_END_MAGIC) {
                        badEnd++;
                    }
                    buf.putInt(16, (int) badEnd);
                }
                case 2 -> { // Unknown item tag (replace item at offset 4 with unknown tag)
                    int badTag = 0x10 + (rng.nextInt(30)); // 0x10..0x2D is not a valid tag
                    buf.putInt(4, badTag);
                }
                case 3 -> { // Truncate pointer payload for item 0x43
                    byte[] trunc = new byte[12]; // truncated right after 0x43 header word, before pointer
                    System.arraycopy(mutated, 0, trunc, 0, 12);
                    mutated = trunc;
                }
                case 4 -> { // Corrupt vector table pointer to out-of-range address
                    long badPtr = 0x00001000L; // outside valid flash/SRAM
                    buf.putInt(12, (int) badPtr);
                }
                default -> throw new IllegalStateException();
            }

            final byte[] testInput = mutated;
            DiagnosticException ex = assertThrows(
                    DiagnosticException.class,
                    () -> RpBootMetadataParser.parseRp2350(testInput, 0x10000000L, false),
                    "RP2350 IMAGE_DEF mutation " + i + " should fail closed with DiagnosticException");

            DiagnosticCode code = ex.diagnostic().code();
            assertEquals(DiagnosticCode.RP_BOOT_METADATA_INVALID, code);
            passedClosed++;
        }

        assertTrue(totalTests >= 256, "Total fuzz tests must be at least 256: " + totalTests);
        assertEquals(totalTests, passedClosed, "All mutated inputs must cleanly fail closed");
    }

    private static byte[] createValidUf2Block(long targetAddr, int blockNo, int numBlocks, long familyId) {
        byte[] block = new byte[512];
        ByteBuffer buf = ByteBuffer.wrap(block).order(ByteOrder.LITTLE_ENDIAN);
        buf.putInt(0, (int) RpUf2Block.EXPECTED_MAGIC_START0);
        buf.putInt(4, (int) RpUf2Block.EXPECTED_MAGIC_START1);
        buf.putInt(8, RpUf2Block.FLAG_FAMILY_ID_PRESENT);
        buf.putInt(12, (int) targetAddr);
        buf.putInt(16, 256); // payload size
        buf.putInt(20, blockNo);
        buf.putInt(24, numBlocks);
        buf.putInt(28, (int) familyId);
        // Payload (256 bytes) filled with NOPs
        for (int i = 32; i < 32 + 256; i++) {
            block[i] = 0;
        }
        buf.putInt(508, (int) RpUf2Block.EXPECTED_MAGIC_END);
        return block;
    }

    private static byte[] createValidRp2040Boot2() {
        byte[] data = new byte[270];
        // 252 bytes of boot2 code
        for (int i = 0; i < 252; i++) {
            data[i] = (byte) (i & 0xFF);
        }
        long crc = Rp2040Boot2Checksum.calculate(data, 0, 252);
        ByteBuffer buf = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
        buf.putInt(252, (int) crc);

        // Vector table at 256
        buf.putInt(256, 0x20040000); // Initial SP (top of SRAM)
        buf.putInt(260, 0x10000101); // Reset vector (Thumb mode bit 0 = 1)
        return data;
    }

    private static byte[] createValidRp2350ImageDef() {
        byte[] data = new byte[64];
        ByteBuffer buf = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
        buf.putInt(0, (int) RpBootMetadataParser.IMAGE_DEF_START_MAGIC);
        buf.putInt(4, 0x00000142); // Item 1: TAG_IMAGE_TYPE (ARMv8-M Secure)
        buf.putInt(8, 0x00000043); // Item 2: TAG_VECTOR_TABLE_OR_ENTRY
        buf.putInt(12, 0x10000100); // Vector table pointer
        buf.putInt(16, (int) RpBootMetadataParser.IMAGE_DEF_END_MAGIC);
        return data;
    }
}
