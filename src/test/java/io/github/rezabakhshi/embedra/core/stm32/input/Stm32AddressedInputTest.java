package io.github.rezabakhshi.embedra.core.stm32.input;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.OptionalLong;
import org.junit.jupiter.api.Test;

class Stm32AddressedInputTest {
    private static final long END = 0x1_0000_0000L;

    @Test
    void elfKeepsEncodedFactsAndImmutableLists() {
        Stm32ElfInput.LoadSegment segment = new Stm32ElfInput.LoadSegment(
            0x08000000L, 0x08000000L, 256, 128, 128, 5);
        Stm32ElfInput.Section section = new Stm32ElfInput.Section(
            ".text", 0x08000080L, 128, 256, 2, 1);
        Stm32ElfInput input = new Stm32ElfInput(0x08000081L,
            List.of(segment), List.of(section));
        assertEquals(Stm32AddressedInput.Format.ELF, input.format());
        assertEquals(0x08000081L, input.encodedEntryPoint().orElseThrow());
        assertEquals(segment, input.loadSegments().getFirst());
        assertTrue(section.allocatable());
        assertFalse(new Stm32ElfInput.Section("debug", 0, 0, 0, 0, 1).allocatable());
        assertThrows(UnsupportedOperationException.class, () -> input.sections().clear());
        assertThrows(NullPointerException.class, () -> new Stm32ElfInput(0, null, List.of()));
        assertThrows(NullPointerException.class, () -> new Stm32ElfInput(0, List.of(), null));
        assertThrows(NullPointerException.class,
            () -> new Stm32ElfInput.Section(null, 0, 0, 0, 0, 1));
    }

    @Test
    void elfRejectsAddressAndSourceRangesOutsideTargetOrInput() {
        assertThrows(IllegalArgumentException.class,
            () -> new Stm32ElfInput(-1, List.of(), List.of()));
        assertThrows(IllegalArgumentException.class,
            () -> new Stm32ElfInput(END, List.of(), List.of()));
        assertThrows(IllegalArgumentException.class,
            () -> new Stm32ElfInput.LoadSegment(0, 0, -1, 0, 0, 0));
        assertThrows(IllegalArgumentException.class,
            () -> new Stm32ElfInput.LoadSegment(END - 1, 0, 2, 0, 0, 0));
        assertThrows(IllegalArgumentException.class,
            () -> new Stm32ElfInput.LoadSegment(0, END - 1, 2, 0, 0, 0));
        assertThrows(IllegalArgumentException.class,
            () -> new Stm32ElfInput.LoadSegment(0, 0, 1, 0, 2, 0));
        assertThrows(IllegalArgumentException.class,
            () -> new Stm32ElfInput.LoadSegment(0, 0, 0, -1, 0, 0));
        assertThrows(IllegalArgumentException.class,
            () -> new Stm32ElfInput.LoadSegment(0, 0, 0, 0, -1, 0));
        assertThrows(ArithmeticException.class,
            () -> new Stm32ElfInput.LoadSegment(0, 0, 1, Long.MAX_VALUE, 1, 0));
        assertThrows(IllegalArgumentException.class,
            () -> new Stm32ElfInput.Section("bad", END - 1, 2, 0, 0, 1));
        assertThrows(IllegalArgumentException.class,
            () -> new Stm32ElfInput.Section("bad", 0, 0, -1, 0, 1));
    }

    @Test
    void intelHexKeepsEncodedFactsAndRejectsInvalidRanges() {
        Stm32IntelHexInput.DataRecord record = new Stm32IntelHexInput.DataRecord(
            0x10040000L, 16, 12, 2);
        Stm32IntelHexInput input = new Stm32IntelHexInput(
            OptionalLong.of(0x10040101L), List.of(record));
        assertEquals(Stm32AddressedInput.Format.INTEL_HEX, input.format());
        assertEquals(0x10040101L, input.encodedEntryPoint().orElseThrow());
        assertEquals(record, input.dataRecords().getFirst());
        assertTrue(new Stm32IntelHexInput(OptionalLong.empty(), List.of())
            .encodedEntryPoint().isEmpty());
        assertThrows(UnsupportedOperationException.class, () -> input.dataRecords().clear());
        assertThrows(NullPointerException.class,
            () -> new Stm32IntelHexInput(null, List.of()));
        assertThrows(NullPointerException.class,
            () -> new Stm32IntelHexInput(OptionalLong.empty(), null));
        assertThrows(IllegalArgumentException.class,
            () -> new Stm32IntelHexInput(OptionalLong.of(-1), List.of()));
        assertThrows(IllegalArgumentException.class,
            () -> new Stm32IntelHexInput(OptionalLong.of(END), List.of()));
        assertThrows(IllegalArgumentException.class,
            () -> new Stm32IntelHexInput.DataRecord(-1, 0, 0, 1));
        assertThrows(IllegalArgumentException.class,
            () -> new Stm32IntelHexInput.DataRecord(END, 0, 0, 1));
        assertThrows(IllegalArgumentException.class,
            () -> new Stm32IntelHexInput.DataRecord(0, -1, 0, 1));
        assertThrows(IllegalArgumentException.class,
            () -> new Stm32IntelHexInput.DataRecord(END - 1, 2, 0, 1));
        assertThrows(IllegalArgumentException.class,
            () -> new Stm32IntelHexInput.DataRecord(0, 0, -1, 1));
        assertThrows(IllegalArgumentException.class,
            () -> new Stm32IntelHexInput.DataRecord(0, 0, 0, 0));
    }
}
