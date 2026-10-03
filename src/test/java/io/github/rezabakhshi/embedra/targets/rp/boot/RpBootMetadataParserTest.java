package io.github.rezabakhshi.embedra.targets.rp.boot;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

public class RpBootMetadataParserTest {

    private static void writeU32Le(byte[] data, int offset, long val) {
        data[offset] = (byte) (val & 0xFF);
        data[offset + 1] = (byte) ((val >> 8) & 0xFF);
        data[offset + 2] = (byte) ((val >> 16) & 0xFF);
        data[offset + 3] = (byte) ((val >> 24) & 0xFF);
    }

    @Test
    void testRp2040Boot2CrcValidAndInvalid() throws Exception {
        byte[] boot2 = new byte[264];
        Arrays.fill(boot2, 0, 252, (byte) 0x55);

        // Compute valid CRC
        long calculated = Rp2040Boot2Checksum.calculate(boot2, 0, 252);
        writeU32Le(boot2, 252, calculated);

        // Vector table at 256: Initial SP 0x20042000, Reset Handler 0x10000141
        writeU32Le(boot2, 256, 0x20042000L);
        writeU32Le(boot2, 260, 0x10000141L);

        assertTrue(Rp2040Boot2Checksum.validate(boot2));

        Rp2040BootMetadata metaValid = RpBootMetadataParser.parseRp2040(boot2, 0x10000000L);
        assertTrue(metaValid.isCrcValid());
        assertEquals(calculated, metaValid.storedCrc());
        assertEquals(calculated, metaValid.calculatedCrc());
        assertFalse(metaValid.isPlaceholder());
        assertTrue(metaValid.isVectorTableValid());
        assertEquals(0x20042000L, metaValid.initialSp());
        assertEquals(0x10000141L, metaValid.entryPoint());

        // Corrupt CRC by flipping byte 0
        boot2[0] ^= 1;
        assertFalse(Rp2040Boot2Checksum.validate(boot2));

        Rp2040BootMetadata metaCorrupt = RpBootMetadataParser.parseRp2040(boot2, 0x10000000L);
        assertFalse(metaCorrupt.isCrcValid());
        assertEquals(calculated, metaCorrupt.storedCrc());
    }

    @Test
    void testRp2040PlaceholderCrc() throws Exception {
        byte[] boot2 = new byte[264];
        writeU32Le(boot2, 252, Rp2040Boot2Checksum.PLACEHOLDER_CRC2);
        writeU32Le(boot2, 256, 0x20042000L);
        writeU32Le(boot2, 260, 0x10000141L);

        Rp2040BootMetadata meta = RpBootMetadataParser.parseRp2040(boot2, 0x10000000L);
        assertTrue(meta.isPlaceholder());
        assertFalse(meta.isCrcValid());
    }

    @Test
    void testRp2040BoundaryErrors() {
        byte[] truncated = new byte[100];
        DiagnosticException ex = assertThrows(DiagnosticException.class, () ->
                RpBootMetadataParser.parseRp2040(truncated, 0x10000000L));
        assertEquals(DiagnosticCode.RP_BOOT_METADATA_INVALID, ex.diagnostic().code());
    }

    @Test
    void testRp2350ArmImageDefParsing() throws Exception {
        byte[] data = new byte[512];
        ByteBuffer buf = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
        buf.putInt((int) RpBootMetadataParser.IMAGE_DEF_START_MAGIC);
        buf.putInt(0x00000142); // Item 1: ARM Secure
        buf.putInt(0x00000043); // Item 2: Vector Table Tag
        buf.putInt(0x10000100); // Pointer: 0x10000100
        buf.putInt((int) RpBootMetadataParser.IMAGE_DEF_END_MAGIC);

        // Vector table at 0x100 (byte 256): Initial SP 0x20082000, Reset Handler 0x10000141
        writeU32Le(data, 256, 0x20082000L);
        writeU32Le(data, 260, 0x10000141L);

        Rp2350BootMetadata meta = RpBootMetadataParser.parseRp2350(data, 0x10000000L, false);
        assertTrue(meta.hasImageDef());
        assertEquals(Rp2350Architecture.ARM, meta.architecture());
        assertEquals(Rp2350SecurityDomain.SECURE, meta.securityDomain());
        assertTrue(meta.vectorTableAddress().isPresent());
        assertEquals(0x10000100L, meta.vectorTableAddress().getAsLong());
        assertEquals(0x10000141L, meta.entryPoint());
        assertTrue(meta.initialSp().isPresent());
        assertEquals(0x20082000L, meta.initialSp().getAsLong());
        assertFalse(meta.isStackedFlash());
        assertEquals("RP2350", meta.series());
    }

    @Test
    void testRp2350RiscvImageDefParsing() throws Exception {
        byte[] data = new byte[512];
        ByteBuffer buf = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
        buf.putInt((int) RpBootMetadataParser.IMAGE_DEF_START_MAGIC);
        buf.putInt(0x00000242); // Item 1: RISC-V
        buf.putInt(0x00000043); // Item 2: Entry Tag
        buf.putInt(0x10000100); // Entry pointer: 0x10000100
        buf.putInt((int) RpBootMetadataParser.IMAGE_DEF_END_MAGIC);

        Rp2350BootMetadata meta = RpBootMetadataParser.parseRp2350(data, 0x10000000L, false);
        assertTrue(meta.hasImageDef());
        assertEquals(Rp2350Architecture.RISCV, meta.architecture());
        assertEquals(0x10000100L, meta.entryPoint());
        assertFalse(meta.vectorTableAddress().isPresent());
    }

    @Test
    void testRp2354StackedFlashFlag() throws Exception {
        byte[] data = new byte[512];
        ByteBuffer buf = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
        buf.putInt((int) RpBootMetadataParser.IMAGE_DEF_START_MAGIC);
        buf.putInt(0x00000142);
        buf.putInt(0x00000043);
        buf.putInt(0x10000100);
        buf.putInt((int) RpBootMetadataParser.IMAGE_DEF_END_MAGIC);

        RpBootMetadata meta = RpBootMetadataParser.parse(data, 0x10000000L, "RP2354A");
        assertEquals("RP2354", meta.series());
        assertTrue(((Rp2350BootMetadata) meta).isStackedFlash());
    }

    @Test
    void testRp2350MalformedMagicAndTruncation() {
        byte[] badMagic = new byte[64];
        writeU32Le(badMagic, 0, 0xDEADBEEFL);
        DiagnosticException ex = assertThrows(DiagnosticException.class, () ->
                RpBootMetadataParser.parseRp2350(badMagic, 0x10000000L, false));
        assertEquals(DiagnosticCode.RP_BOOT_METADATA_INVALID, ex.diagnostic().code());

        // Truncated item pointer (item 0x43 without pointer word)
        byte[] truncatedItem = new byte[8];
        writeU32Le(truncatedItem, 0, RpBootMetadataParser.IMAGE_DEF_START_MAGIC);
        writeU32Le(truncatedItem, 4, 0x00000043L);
        DiagnosticException ex2 = assertThrows(DiagnosticException.class, () ->
                RpBootMetadataParser.parseRp2350(truncatedItem, 0x10000000L, false));
        assertEquals(DiagnosticCode.RP_BOOT_METADATA_INVALID, ex2.diagnostic().code());
    }

    @Test
    void testRp2350TagLastWithLinkAndEndMarker() throws Exception {
        byte[] data = new byte[512];
        ByteBuffer buf = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
        buf.putInt((int) RpBootMetadataParser.IMAGE_DEF_START_MAGIC);
        buf.putInt(0x00000142); // Item 1: ARM Secure
        buf.putInt(0x00000043); // Item 2: Vector Table Tag
        buf.putInt(0x10000100); // Pointer
        buf.putInt(0x000100ff); // Item 3: TAG_LAST (PICOBIN_BLOCK_ITEM_2BS_LAST)
        buf.putInt(0x00000000); // Link to next block (0 = loop)
        buf.putInt((int) RpBootMetadataParser.IMAGE_DEF_END_MAGIC);

        writeU32Le(data, 256, 0x20082000L);
        writeU32Le(data, 260, 0x10000141L);

        Rp2350BootMetadata meta = RpBootMetadataParser.parseRp2350(data, 0x10000000L, false);
        assertTrue(meta.hasImageDef());
        assertEquals(Rp2350Architecture.ARM, meta.architecture());
        assertEquals(0x10000141L, meta.entryPoint());
    }

    @Test
    void testRp2350TagLastWithoutEndMarker() throws Exception {
        byte[] data = new byte[512];
        ByteBuffer buf = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
        buf.putInt((int) RpBootMetadataParser.IMAGE_DEF_START_MAGIC);
        buf.putInt(0x00000142); // Item 1: ARM Secure
        buf.putInt(0x00000043); // Item 2: Vector Table Tag
        buf.putInt(0x10000100); // Pointer
        buf.putInt(0x000100ff); // Item 3: TAG_LAST
        buf.putInt(0x00000000); // Link word
        // No IMAGE_DEF_END_MAGIC, followed by zeros

        writeU32Le(data, 256, 0x20082000L);
        writeU32Le(data, 260, 0x10000141L);

        Rp2350BootMetadata meta = RpBootMetadataParser.parseRp2350(data, 0x10000000L, false);
        assertTrue(meta.hasImageDef());
        assertEquals(Rp2350Architecture.ARM, meta.architecture());
        assertEquals(0x10000141L, meta.entryPoint());
    }

    @Test
    void testRp2350MinimumViableImageDefAfterVectorTable() throws Exception {
        byte[] data = new byte[512];
        // Vector table at offset 0: Initial SP + Reset Handler
        writeU32Le(data, 0, 0x20082000L);
        writeU32Le(data, 4, 0x10000201L);

        // Minimum viable image def at offset 256: Start magic, Image type, Tag last
        ByteBuffer buf = ByteBuffer.wrap(data, 256, 256).order(ByteOrder.LITTLE_ENDIAN);
        buf.putInt((int) RpBootMetadataParser.IMAGE_DEF_START_MAGIC);
        buf.putInt(0x00000142); // ARM Secure
        buf.putInt(0x000100ff); // TAG_LAST
        buf.putInt(0x00000000); // link

        Rp2350BootMetadata meta = RpBootMetadataParser.parseRp2350(data, 0x10000000L, false);
        assertTrue(meta.hasImageDef());
        assertEquals(Rp2350Architecture.ARM, meta.architecture());
        assertTrue(meta.vectorTableAddress().isPresent());
        assertEquals(0x10000000L, meta.vectorTableAddress().getAsLong());
        assertEquals(0x10000201L, meta.entryPoint());
        assertTrue(meta.initialSp().isPresent());
        assertEquals(0x20082000L, meta.initialSp().getAsLong());
    }
}
