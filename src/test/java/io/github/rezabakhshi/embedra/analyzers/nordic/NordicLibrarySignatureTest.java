package io.github.rezabakhshi.embedra.analyzers.nordic;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import org.junit.jupiter.api.Test;

class NordicLibrarySignatureTest {

    private static final String DIGEST = "2a9754f9a56291a89c323f4625b525d8c3681432f418d184715f8d9b626488a0";

    private static final byte[] PATTERN = {
        0x10, (byte) 0xB5, 0x73, (byte) 0xDF, 0x10, (byte) 0xBD, 0x00, (byte) 0xBF
    };

    @Test
    void exposesDefensiveCopiesAndMatchesMaskedBytes() {
        byte[] mask = {(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 0, 0, (byte) 0xFF, (byte) 0xFF};
        NordicLibrarySignature sig = new NordicLibrarySignature(
                "nrf5.ble.adv_start", "NRF5_SDK", "BLE", "sd_ble_gap_adv_start",
                "nRF52", "ANY", "-O2", "ble_gap.h", DIGEST, PATTERN, mask);

        assertFalse(sig.isFullySpecified());
        assertTrue(sig.matches(new byte[] {
            0x10, (byte) 0xB5, 0x73, (byte) 0xDF, (byte) 0x99, (byte) 0xAA, 0x00, (byte) 0xBF
        }));
        assertFalse(sig.matches(new byte[] {
            0x10, (byte) 0xB5, 0x73, (byte) 0xDF, (byte) 0x99, (byte) 0xAA, 0x00, (byte) 0x00
        }));
        assertFalse(sig.matches(new byte[] {0x10, (byte) 0xB5}));

        byte[] returned = sig.pattern();
        returned[0] = 0;
        assertArrayEquals(PATTERN, sig.pattern());
        assertEquals(DIGEST, sig.sourceSha256());
    }

    @Test
    void fullySpecifiedMaskIsReported() {
        byte[] mask = new byte[PATTERN.length];
        Arrays.fill(mask, (byte) 0xFF);
        NordicLibrarySignature sig = new NordicLibrarySignature(
                "nrf5.ble.adv_start", "NRF5_SDK", "BLE", "sd_ble_gap_adv_start",
                "nRF52", "ANY", "-O2", "ble_gap.h", DIGEST, PATTERN, mask);
        assertTrue(sig.isFullySpecified());
    }

    @Test
    void rejectsMalformedPatternsAndMasks() {
        byte[] allFf = new byte[PATTERN.length];
        Arrays.fill(allFf, (byte) 0xFF);

        // Length < 8
        assertThrows(IllegalArgumentException.class, () ->
                new NordicLibrarySignature("id", "lib", "subsys", "fn", "nRF52", "ANY", "-O2",
                        "src.c", DIGEST, new byte[4], new byte[4]));

        // Mask length mismatch
        assertThrows(IllegalArgumentException.class, () ->
                new NordicLibrarySignature("id", "lib", "subsys", "fn", "nRF52", "ANY", "-O2",
                        "src.c", DIGEST, PATTERN, new byte[10]));

        // Non-00/FF mask
        byte[] invalidMask = allFf.clone();
        invalidMask[1] = 0x55;
        assertThrows(IllegalArgumentException.class, () ->
                new NordicLibrarySignature("id", "lib", "subsys", "fn", "nRF52", "ANY", "-O2",
                        "src.c", DIGEST, PATTERN, invalidMask));

        // Invalid digest
        assertThrows(IllegalArgumentException.class, () ->
                new NordicLibrarySignature("id", "lib", "subsys", "fn", "nRF52", "ANY", "-O2",
                        "src.c", "not-a-digest", PATTERN, allFf));
    }
}
