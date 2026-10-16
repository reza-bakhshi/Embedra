package io.github.rezabakhshi.embedra.analyzers.stm8;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import org.junit.jupiter.api.Test;

class Stm8LibrarySignatureTest {

    private static final String DIGEST = "2967854c80487989641778f78bbb9ca6c7c804643cb71c1a2698fe29defeb047";

    private static final byte[] PATTERN = {
        (byte) 0x89, (byte) 0x88, 0x7B, 0x03, (byte) 0xA1, 0x00, 0x27, 0x05
    };

    @Test
    void exposesDefensiveCopiesAndMatchesMaskedBytes() {
        byte[] mask = {(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 0, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF};
        Stm8LibrarySignature sig = new Stm8LibrarySignature(
                "stm8s.spl.gpio_init", "STM8_SPL", "GPIO", "GPIO_Init",
                "STM8S", "SDCC", "-Os", "stm8s_gpio.c", DIGEST, PATTERN, mask);

        assertFalse(sig.isFullySpecified());
        assertTrue(sig.matches(new byte[] {
            (byte) 0x89, (byte) 0x88, 0x7B, (byte) 0x99, (byte) 0xA1, 0x00, 0x27, 0x05
        }));
        assertFalse(sig.matches(new byte[] {
            (byte) 0x89, (byte) 0x88, 0x7B, (byte) 0x99, (byte) 0xA1, 0x00, 0x27, 0x00
        }));
        assertFalse(sig.matches(new byte[] {(byte) 0x89, (byte) 0x88}));

        byte[] returned = sig.pattern();
        returned[0] = 0;
        assertArrayEquals(PATTERN, sig.pattern());
        assertEquals(DIGEST, sig.sourceSha256());
    }

    @Test
    void fullySpecifiedMaskIsReported() {
        byte[] mask = new byte[PATTERN.length];
        Arrays.fill(mask, (byte) 0xFF);
        Stm8LibrarySignature sig = new Stm8LibrarySignature(
                "stm8s.spl.clk_deinit", "STM8_SPL", "CLK", "CLK_DeInit",
                "STM8S", "SDCC", "-Os", "stm8s_clk.c", DIGEST, PATTERN, mask);
        assertTrue(sig.isFullySpecified());
    }

    @Test
    void rejectsMalformedPatternsAndMasks() {
        byte[] allFf = new byte[PATTERN.length];
        Arrays.fill(allFf, (byte) 0xFF);

        // Length < 8
        assertThrows(IllegalArgumentException.class, () ->
                new Stm8LibrarySignature("id", "lib", "comp", "fn", "STM8S", "SDCC", "-Os",
                        "src.c", DIGEST, new byte[4], new byte[4]));

        // Mask length mismatch
        assertThrows(IllegalArgumentException.class, () ->
                new Stm8LibrarySignature("id", "lib", "comp", "fn", "STM8S", "SDCC", "-Os",
                        "src.c", DIGEST, PATTERN, new byte[PATTERN.length - 1]));

        // Mask invalid values (not 0 or 0xFF)
        assertThrows(IllegalArgumentException.class, () ->
                new Stm8LibrarySignature("id", "lib", "comp", "fn", "STM8S", "SDCC", "-Os",
                        "src.c", DIGEST, PATTERN,
                        new byte[] {
                            (byte) 0xFF, 0x0F, (byte) 0xFF, (byte) 0xFF,
                            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF
                        }));

        // All-zero mask
        assertThrows(IllegalArgumentException.class, () ->
                new Stm8LibrarySignature("id", "lib", "comp", "fn", "STM8S", "SDCC", "-Os",
                        "src.c", DIGEST, PATTERN, new byte[PATTERN.length]));

        // Invalid SHA-256 digest
        assertThrows(IllegalArgumentException.class, () ->
                new Stm8LibrarySignature("id", "lib", "comp", "fn", "STM8S", "SDCC", "-Os",
                        "src.c", "not-a-digest", PATTERN, allFf));
    }
}
