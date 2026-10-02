package io.github.rezabakhshi.embedra.targets.stm32.catalog;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.stm32.input.Stm32RawBinPlan;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.TreeSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class Stm32DevicePackRegistryTest {
    private static final Path SELECTION = Path.of(
        "catalogs/stm32/2026-09-29/selection.json");

    private static final Path CATALOG = Path.of(
        "catalogs/stm32/2026-09-29/curated-catalog.json");

    @TempDir
    Path temporary;

    @Test
    void coversFiftyThreeExactRecordsWithoutPromotingSupport() throws Exception {
        var registry = load();
        assertEquals(53, registry.size());
        assertEquals(20, registry.families().size());
        assertEquals(new ArrayList<>(new TreeSet<>(registry.families())),
            new ArrayList<>(registry.families()));
        for (var part : registry.parts()) {
            assertEquals("PLANNED", part.supportState());
            assertEquals("UNKNOWN", part.lifecycle());
            assertEquals("CATALOG_ONLY", part.packStatus());
            assertFalse(part.exactPart().contains("*"));
        }
        var f103 = registry.selectExact("STM32F103C8T6");
        assertEquals("LQFP48", f103.packageName());
        assertEquals(64, f103.flashKiB().orElseThrow());
        assertEquals(List.of("ARM Cortex-M3"), f103.cores());
        assertEquals(128, registry.selectExact("STM32F103CBT6")
            .flashKiB().orElseThrow());
        var uncertain = registry.selectExact("STM32C031C6T3");
        assertTrue(uncertain.flashKiB().isEmpty());
        assertEquals(List.of(16, 32), uncertain.flashCandidatesKiB());
        var n6 = registry.selectExact("STM32N657X0H3Q");
        assertEquals(List.of("ARM Cortex-M55"), n6.cores());
        assertEquals(0, n6.flashKiB().orElseThrow());
        assertEquals("STM32N657X0H3Q", Stm32RawBinPlan.explicit(
            n6.exactPart(), 0x34000000L, 4, registry, ParserLimits.defaults())
            .exactPart());
    }

    @Test
    void searchShowsAmbiguityAndNeverSelectsFamilyOrPrefix() throws Exception {
        var registry = load();
        assertEquals(3, registry.search("stm32f103").size());
        assertEquals(3, registry.search(" F103 ").size());
        assertEquals(Stm32DevicePackRegistry.SearchStatus.AMBIGUOUS,
            registry.resolve("STM32F103").status());
        assertEquals(Stm32DevicePackRegistry.SearchStatus.SINGLE_CANDIDATE,
            registry.resolve("F103C8T6").status());
        assertEquals(Stm32DevicePackRegistry.SearchStatus.EXACT_ID,
            registry.resolve("STM32F103C8T6").status());
        assertEquals(Stm32DevicePackRegistry.SearchStatus.NO_MATCH,
            registry.resolve("not-a-part").status());
        assertEquals("STM32F103C8T6", registry.search("stm32f103c8t6")
            .getFirst().exactPart());
        assertTrue(registry.search("not-a-part").isEmpty());
        assertThrows(IllegalArgumentException.class,
            () -> registry.selectExact("STM32F103"));
        assertThrows(IllegalArgumentException.class,
            () -> registry.selectExact("stm32f103c8t6"));
        assertThrows(IllegalArgumentException.class,
            () -> registry.selectExact("STM32F103C*T6"));
    }

    @Test
    void searchIsCaseInsensitiveForLineLabelsWithLowercaseText() throws Exception {
        var registry = load();
        assertEquals(3, registry.search("stm32c0x1").size());
        assertEquals(Stm32DevicePackRegistry.SearchStatus.SINGLE_CANDIDATE,
            registry.resolve("h750 value line").status());
        assertEquals("STM32H750XBH6",
            registry.search("h750 value line").getFirst().exactPart());
    }

    @Test
    void rejectsTamperedMissingAndWrongSelection() throws Exception {
        var ids = Stm32CuratedPartIds.load(SELECTION, ParserLimits.defaults(),
            CancellationToken.none());
        assertThrows(IOException.class, () -> Stm32DevicePackRegistry.load(
            temporary.resolve("missing.json"), ids, ParserLimits.defaults(),
            CancellationToken.none()));
        byte[] changed = Files.readAllBytes(CATALOG);
        changed[0] ^= 1;
        Path tampered = temporary.resolve("catalog.json");
        Files.write(tampered, changed);
        assertThrows(IOException.class, () -> Stm32DevicePackRegistry.load(
            tampered, ids, ParserLimits.defaults(), CancellationToken.none()));
        assertThrows(IOException.class, () -> Stm32DevicePackRegistry.load(
            CATALOG, part -> true, ParserLimits.defaults(), CancellationToken.none()));
    }

    private static Stm32DevicePackRegistry load() throws Exception {
        var ids = Stm32CuratedPartIds.load(SELECTION, ParserLimits.defaults(),
            CancellationToken.none());
        return Stm32DevicePackRegistry.load(CATALOG, ids, ParserLimits.defaults(),
            CancellationToken.none());
    }
}
