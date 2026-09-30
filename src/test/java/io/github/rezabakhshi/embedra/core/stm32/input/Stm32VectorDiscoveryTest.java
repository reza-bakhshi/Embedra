package io.github.rezabakhshi.embedra.core.stm32.input;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import java.io.IOException;
import java.util.List;
import java.util.Objects;
import java.time.Duration;
import org.junit.jupiter.api.Test;

class Stm32VectorDiscoveryTest {
    private static final long BASE = 0x08000000L;

    @Test
    void findsGoldenAndRequiresExplicitConfirmation() throws Exception {
        byte[] bytes = fixture();
        var candidates = Stm32VectorDiscovery.discover(bytes, BASE,
            List.of(new Stm32VectorDiscovery.AddressRange(0x20000000L, 0x20005000L)),
            ParserLimits.defaults(), CancellationToken.none());
        assertEquals(1, candidates.size());
        var candidate = candidates.getFirst();
        assertEquals(0, candidate.sourceOffset());
        assertEquals(BASE, candidate.tableAddress());
        assertEquals(0x20005000L, candidate.initialStackPointer());
        assertEquals(0x08000101L, candidate.resetHandler());
        assertTrue(candidate.score() > 0);
        assertThrows(IllegalArgumentException.class,
            () -> Stm32VectorDiscovery.confirm(candidates, BASE + 0x100));
        assertEquals(candidate, Stm32VectorDiscovery.confirm(candidates, BASE).candidate());
    }

    @Test
    void findsRelocatedTableAndRejectsDecoys() throws Exception {
        byte[] golden = fixture();
        byte[] relocated = new byte[0x100 + golden.length];
        System.arraycopy(golden, 0, relocated, 0x100, golden.length);
        // Adjust Thumb handlers to the relocated image address.
        for (int offset = 4; offset < 64; offset += 4) {
            relocated[0x100 + offset + 1] += 1;
        }
        var candidates = Stm32VectorDiscovery.discover(relocated, BASE,
            List.of(new Stm32VectorDiscovery.AddressRange(0x20000000L, 0x20005000L)),
            ParserLimits.defaults(), CancellationToken.none());
        assertEquals(0x100, candidates.getFirst().sourceOffset());
        assertEquals(BASE + 0x100, candidates.getFirst().tableAddress());
        assertThrows(IllegalArgumentException.class,
            () -> Stm32VectorDiscovery.confirm(candidates, BASE));

        byte[] decoy = fixture();
        decoy[3] = 0; // Initial SP outside supplied RAM.
        assertTrue(Stm32VectorDiscovery.discover(decoy, BASE,
            List.of(new Stm32VectorDiscovery.AddressRange(0x20000000L, 0x20005000L)),
            ParserLimits.defaults(), CancellationToken.none()).isEmpty());
        decoy = fixture();
        decoy[4] = 0; // Reset handler loses the Thumb bit.
        assertTrue(Stm32VectorDiscovery.discover(decoy, BASE,
            List.of(new Stm32VectorDiscovery.AddressRange(0x20000000L, 0x20005000L)),
            ParserLimits.defaults(), CancellationToken.none()).isEmpty());
    }

    @Test
    void refusesUnsupportedBaseAndCancellation() throws Exception {
        byte[] bytes = fixture();
        var ram = List.of(new Stm32VectorDiscovery.AddressRange(0x20000000L, 0x20005000L));
        assertThrows(IllegalArgumentException.class, () -> Stm32VectorDiscovery.discover(
            bytes, 0x1_0000_0000L, ram, ParserLimits.defaults(), CancellationToken.none()));
        assertThrows(Exception.class, () -> Stm32VectorDiscovery.discover(
            bytes, BASE, ram, ParserLimits.defaults(), () -> true));
        assertThrows(IllegalArgumentException.class, () -> Stm32VectorDiscovery.discover(
            bytes, -1, ram, ParserLimits.defaults(), CancellationToken.none()));
        assertThrows(IllegalArgumentException.class, () -> Stm32VectorDiscovery.discover(
            bytes, 0xfffffff0L, ram, ParserLimits.defaults(), CancellationToken.none()));
        assertThrows(IllegalArgumentException.class, () -> Stm32VectorDiscovery.discover(
            bytes, BASE, List.of(), ParserLimits.defaults(), CancellationToken.none()));
        ParserLimits small = new ParserLimits(1, 1, 1, 1, 1, Duration.ofSeconds(1));
        assertThrows(IllegalArgumentException.class, () -> Stm32VectorDiscovery.discover(
            bytes, BASE, ram, small, CancellationToken.none()));
        ParserLimits instant = new ParserLimits(1000, 1000, 1000, 10, 1,
            Duration.ofNanos(1));
        assertThrows(IllegalArgumentException.class, () -> Stm32VectorDiscovery.discover(
            bytes, BASE, ram, instant, CancellationToken.none()));
    }

    @Test
    void rejectsInvalidRamRangesSparseAndBadHandlers() throws Exception {
        assertThrows(IllegalArgumentException.class,
            () -> new Stm32VectorDiscovery.AddressRange(-1, 10));
        assertThrows(IllegalArgumentException.class,
            () -> new Stm32VectorDiscovery.AddressRange(1, 0x1_0000_0001L));
        assertThrows(IllegalArgumentException.class,
            () -> new Stm32VectorDiscovery.AddressRange(10, 10));
        var ram = new Stm32VectorDiscovery.AddressRange(0x20000000L, 0x20005000L);
        assertTrue(ram.containsStackTop(0x20005000L));
        assertTrue(!ram.containsStackTop(0x20000000L));
        assertTrue(!ram.containsStackTop(0x20005001L));
        assertThrows(IllegalArgumentException.class, () ->
            new Stm32VectorDiscovery.Candidate(0, BASE, 0, 0,
                List.of(0L), 0, "unknown"));

        byte[] sparse = fixture();
        for (int offset = 8; offset < 64; offset++) {
            sparse[offset] = 0;
        }
        assertTrue(Stm32VectorDiscovery.discover(sparse, BASE, List.of(ram),
            ParserLimits.defaults(), CancellationToken.none()).isEmpty());
        byte[] invalid = fixture();
        invalid[8] = 4;
        invalid[12] = 4;
        invalid[16] = 4;
        assertTrue(Stm32VectorDiscovery.discover(invalid, BASE, List.of(ram),
            ParserLimits.defaults(), CancellationToken.none()).isEmpty());
        assertEquals(1, Stm32VectorDiscovery.discover(fixture(), BASE + 4,
            List.of(ram), ParserLimits.defaults(), CancellationToken.none()).size());
    }

    private static byte[] fixture() throws IOException {
        try (var input = Objects.requireNonNull(Stm32VectorDiscoveryTest.class
                .getResourceAsStream("/fixtures/stm32f103/STM32F103C8T6.bin"))) {
            return input.readAllBytes();
        }
    }
}
