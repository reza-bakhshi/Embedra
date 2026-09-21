package io.github.rezabakhshi.embedra.core.io;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class CheckedRangesTest {
    @Test
    void sourceRangeUsesHalfOpenCheckedArithmetic() {
        SourceRange range = new SourceRange(4, 6);

        assertEquals(10, range.endExclusive());
        assertFalse(range.contains(3));
        assertTrue(range.contains(4));
        assertTrue(range.contains(9));
        assertFalse(range.contains(10));
        assertTrue(range.contains(new SourceRange(6, 2)));
        assertFalse(range.contains(new SourceRange(3, 2)));
        assertFalse(range.contains(new SourceRange(9, 2)));
        assertEquals(new SourceRange(6, 2), range.subrange(2, 2));
    }

    @Test
    void sourceRangeRejectsInvalidAndOverflowingValues() {
        assertThrows(IllegalArgumentException.class, () -> new SourceRange(-1, 1));
        assertThrows(IllegalArgumentException.class, () -> new SourceRange(0, -1));
        assertThrows(ArithmeticException.class, () -> new SourceRange(Long.MAX_VALUE, 1));

        SourceRange range = new SourceRange(10, 5);
        assertThrows(IllegalArgumentException.class, () -> range.subrange(-1, 1));
        assertThrows(IllegalArgumentException.class, () -> range.subrange(4, 2));
    }

    @Test
    void addressRangesKeepAddressSpacesDistinct() {
        AddressRange left = new AddressRange("cpu", 0x1000, 0x20);
        AddressRange overlap = new AddressRange("cpu", 0x1010, 0x20);
        AddressRange adjacent = new AddressRange("cpu", 0x1020, 0x20);
        AddressRange otherSpace = new AddressRange("flash-offset", 0x1010, 0x20);

        assertTrue(left.overlaps(overlap));
        assertFalse(left.overlaps(adjacent));
        assertFalse(left.overlaps(otherSpace));
        assertEquals(new AddressRange("cpu", 0x1010, 0x10), left.intersection(overlap).orElseThrow());
        assertTrue(left.intersection(otherSpace).isEmpty());
    }

    @Test
    void addressRangeRejectsBlankSpaceAndOverflow() {
        assertThrows(IllegalArgumentException.class, () -> new AddressRange(" ", 0, 1));
        assertThrows(IllegalArgumentException.class, () -> new AddressRange("cpu", -1, 1));
        assertThrows(IllegalArgumentException.class, () -> new AddressRange("cpu", 0, -1));
        assertThrows(ArithmeticException.class, () -> new AddressRange("cpu", Long.MAX_VALUE, 1));
    }
}
