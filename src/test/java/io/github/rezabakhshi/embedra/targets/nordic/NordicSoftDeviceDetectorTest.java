package io.github.rezabakhshi.embedra.targets.nordic;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.targets.nordic.softdevice.NordicSoftDeviceDetector;
import io.github.rezabakhshi.embedra.targets.nordic.softdevice.NordicSoftDeviceInfo;
import io.github.rezabakhshi.embedra.targets.nordic.softdevice.NordicSoftDeviceType;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for NordicSoftDeviceDetector (T099).
 */
class NordicSoftDeviceDetectorTest {

    private static final Path FIXTURE_DIR = Path.of("src/test/resources/fixtures/nordic");

    @Test
    void hasMbrIdentifiesValidMbrHeader() {
        byte[] mbrBytes = new byte[128];
        ByteBuffer buf = ByteBuffer.wrap(mbrBytes).order(ByteOrder.LITTLE_ENDIAN);
        buf.putInt(0, 0x20001000); // SRAM SP
        buf.putInt(4, 0x000000A1); // Reset vector < 0x1000 with Thumb bit set

        assertTrue(NordicSoftDeviceDetector.hasMbr(mbrBytes, 0x00000000L));
        assertFalse(NordicSoftDeviceDetector.hasMbr(mbrBytes, 0x00001000L)); // wrong base
    }

    @Test
    void detectIdentifiesS132SoftDeviceAndRelocationOffset() {
        // Construct synthetic S132 layout
        int totalSize = 0x00027000;
        byte[] flash = new byte[totalSize];
        ByteBuffer buf = ByteBuffer.wrap(flash).order(ByteOrder.LITTLE_ENDIAN);

        // MBR at 0x00000000
        buf.putInt(0, 0x20001000);
        buf.putInt(4, 0x000000A1);

        // SD at 0x00001000
        buf.putInt(0x1000, 0x20002000);
        buf.putInt(0x1004, 0x000010A1);

        // App at S132 offset (0x00026000)
        buf.putInt(0x26000, 0x20010000);
        buf.putInt(0x26004, 0x00026101);

        Optional<NordicSoftDeviceInfo> opt = NordicSoftDeviceDetector.detect(flash, 0x00000000L);
        assertTrue(opt.isPresent(), "S132 SoftDevice should be detected");
        NordicSoftDeviceInfo info = opt.get();

        assertEquals(NordicSoftDeviceType.S132, info.type());
        assertEquals(0x00026000L, info.applicationOffset());
        assertTrue(info.mbrPresent());
        assertEquals(0x00001000L, info.mbrSizeBytes());
    }

    @Test
    void detectIdentifiesS140SoftDeviceAndRelocationOffset() {
        // Construct synthetic S140 layout
        int totalSize = 0x00028000;
        byte[] flash = new byte[totalSize];
        ByteBuffer buf = ByteBuffer.wrap(flash).order(ByteOrder.LITTLE_ENDIAN);

        // MBR at 0x00000000
        buf.putInt(0, 0x20001000);
        buf.putInt(4, 0x000000A1);

        // SD at 0x00001000
        buf.putInt(0x1000, 0x20002000);
        buf.putInt(0x1004, 0x000010A1);

        // App at S140 offset (0x00027000)
        buf.putInt(0x27000, 0x20040000);
        buf.putInt(0x27004, 0x00027101);

        Optional<NordicSoftDeviceInfo> opt = NordicSoftDeviceDetector.detect(flash, 0x00000000L);
        assertTrue(opt.isPresent(), "S140 SoftDevice should be detected");
        NordicSoftDeviceInfo info = opt.get();

        assertEquals(NordicSoftDeviceType.S140, info.type());
        assertEquals(0x00027000L, info.applicationOffset());
        assertTrue(info.mbrPresent());
    }

    @Test
    void relocateApplicationVectorSucceedsOnValidVector() throws Exception {
        byte[] flash = new byte[0x30000];
        ByteBuffer buf = ByteBuffer.wrap(flash).order(ByteOrder.LITTLE_ENDIAN);
        buf.putInt(0x26000, 0x20010000);
        buf.putInt(0x26004, 0x00026101);

        long entry = NordicSoftDeviceDetector.relocateApplicationVector(flash, 0x00000000L, 0x00026000L);
        assertEquals(0x00026100L, entry); // Aligned Thumb entry address
    }

    @Test
    void relocateApplicationVectorThrowsOnInvalidVector() {
        byte[] flash = new byte[0x30000]; // zeros
        assertThrows(DiagnosticException.class, () ->
            NordicSoftDeviceDetector.relocateApplicationVector(flash, 0x00000000L, 0x00026000L)
        );
    }

    @Test
    void discoverBootloaderAddressExtractsAddressFromUicr() {
        byte[] uicr = new byte[0x100];
        ByteBuffer buf = ByteBuffer.wrap(uicr).order(ByteOrder.LITTLE_ENDIAN);
        buf.putInt(0x14, 0x000F8000); // BOOTLOADERADDR at offset 0x14

        Optional<Long> blOpt = NordicSoftDeviceDetector.discoverBootloaderAddress(uicr);
        assertTrue(blOpt.isPresent());
        assertEquals(0x000F8000L, blOpt.get());

        // All 0xFF (unprogrammed) returns empty
        byte[] emptyUicr = new byte[0x100];
        ByteBuffer emptyBuf = ByteBuffer.wrap(emptyUicr).order(ByteOrder.LITTLE_ENDIAN);
        emptyBuf.putInt(0x14, 0xFFFFFFFF);
        assertTrue(NordicSoftDeviceDetector.discoverBootloaderAddress(emptyUicr).isEmpty());
    }
}
