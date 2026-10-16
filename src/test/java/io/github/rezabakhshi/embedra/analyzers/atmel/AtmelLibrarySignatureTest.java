package io.github.rezabakhshi.embedra.analyzers.atmel;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import org.junit.jupiter.api.Test;

class AtmelLibrarySignatureTest {

    private static final String DIGEST = "2a9754f9a56291a89c323f4625b525d8c3681432f418d184715f8d9b626488a0";

    private static final byte[] PATTERN = {
        0x10, (byte) 0xB5, 0x73, (byte) 0xDF, 0x10, (byte) 0xBD, 0x00, (byte) 0xBF
    };

    @Test
    void exposesDefensiveCopiesAndMatchesMaskedBytes() {
        byte[] mask = {(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 0, 0, (byte) 0xFF, (byte) 0xFF};
        AtmelLibrarySignature sig = new AtmelLibrarySignature(
                "arduino.test.sig", "ARDUINO_CORE", "GPIO", "testFn",
                "AVR8", "ATmega", "AVR_GCC", "-Os", "wiring.c", DIGEST, PATTERN, mask);

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
        AtmelLibrarySignature sig = new AtmelLibrarySignature(
                "arduino.test.sig", "ARDUINO_CORE", "GPIO", "testFn",
                "AVR8", "ATmega", "AVR_GCC", "-Os", "wiring.c", DIGEST, PATTERN, mask);
        assertTrue(sig.isFullySpecified());
    }

    @Test
    void rejectsMalformedPatternsAndMasks() {
        byte[] allFf = new byte[PATTERN.length];
        Arrays.fill(allFf, (byte) 0xFF);

        // Length < 8
        assertThrows(IllegalArgumentException.class, () ->
                new AtmelLibrarySignature("id", "lib", "subsys", "fn", "AVR8", "ATmega", "ANY", "-O2",
                        "src.c", DIGEST, new byte[4], new byte[4]));

        // Mismatched lengths
        assertThrows(IllegalArgumentException.class, () ->
                new AtmelLibrarySignature("id", "lib", "subsys", "fn", "AVR8", "ATmega", "ANY", "-O2",
                        "src.c", DIGEST, PATTERN, new byte[10]));

        // Invalid mask values (non 00/ff)
        byte[] badMask = allFf.clone();
        badMask[2] = 0x55;
        assertThrows(IllegalArgumentException.class, () ->
                new AtmelLibrarySignature("id", "lib", "subsys", "fn", "AVR8", "ATmega", "ANY", "-O2",
                        "src.c", DIGEST, PATTERN, badMask));

        // Invalid digest
        assertThrows(IllegalArgumentException.class, () ->
                new AtmelLibrarySignature("id", "lib", "subsys", "fn", "AVR8", "ATmega", "ANY", "-O2",
                        "src.c", "not-a-sha256", PATTERN, allFf));
    }
}
