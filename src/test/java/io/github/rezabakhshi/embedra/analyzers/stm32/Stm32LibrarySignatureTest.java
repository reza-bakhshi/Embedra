package io.github.rezabakhshi.embedra.analyzers.stm32;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class Stm32LibrarySignatureTest {
    private static final byte[] PATTERN =
        {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte) 0x88};

    @Test
    void exposesDefensiveCopiesAndMatchesMaskedBytes() {
        byte[] mask = {(byte) 0xff, (byte) 0xff, (byte) 0xff, 0, (byte) 0xff,
            (byte) 0xff, (byte) 0xff, (byte) 0xff};
        Stm32LibrarySignature signature = Stm32SignatureTestSupport.signature(
            "stm32f1.hal.Foo.Os", "Foo", PATTERN, mask);
        assertFalse(signature.isFullySpecified());
        assertTrue(signature.matches(
            new byte[] {0x11, 0x22, 0x33, (byte) 0xAA, 0x55, 0x66, 0x77, (byte) 0x88}));
        assertFalse(signature.matches(
            new byte[] {0x11, 0x22, 0x33, (byte) 0xAA, 0x55, 0x66, 0x77, 0x00}));
        assertFalse(signature.matches(new byte[] {0x11, 0x22}));
        assertFalse(signature.matches(
            new byte[] {(byte) 0x99, 0x22, 0x33, (byte) 0xAA, 0x55, 0x66, 0x77, (byte) 0x88}));

        byte[] returned = signature.pattern();
        returned[0] = 0;
        assertArrayEquals(PATTERN, signature.pattern());
        assertEquals(Stm32SignatureTestSupport.SOURCE_SHA, signature.sourceSha256());
    }

    @Test
    void fullySpecifiedMaskIsReported() {
        Stm32LibrarySignature signature = Stm32SignatureTestSupport.signature(
            "stm32f1.hal.Bar.Os", "Bar", PATTERN,
            Stm32SignatureTestSupport.allSpecifiedMask(PATTERN.length));
        assertTrue(signature.isFullySpecified());
    }

    @Test
    void rejectsMalformedPatternsAndMasks() {
        assertThrows(IllegalArgumentException.class, () ->
            Stm32SignatureTestSupport.signature("id", "Fn", new byte[4], new byte[4]));
        assertThrows(IllegalArgumentException.class, () ->
            Stm32SignatureTestSupport.signature("id", "Fn", PATTERN,
                Stm32SignatureTestSupport.allSpecifiedMask(PATTERN.length - 1)));
        assertThrows(IllegalArgumentException.class, () ->
            Stm32SignatureTestSupport.signature("id", "Fn", PATTERN,
                new byte[] {(byte) 0xff, 0x0f, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                    (byte) 0xff, (byte) 0xff, (byte) 0xff}));
        assertThrows(IllegalArgumentException.class, () ->
            Stm32SignatureTestSupport.signature("id", "Fn", PATTERN, new byte[PATTERN.length]));
        assertThrows(IllegalArgumentException.class, () ->
            new Stm32LibrarySignature("id", "lib", "component", "Fn", "STM32F1",
                "gcc", "-Os", "file.c", "not-a-digest", PATTERN,
                Stm32SignatureTestSupport.allSpecifiedMask(PATTERN.length)));
    }
}
