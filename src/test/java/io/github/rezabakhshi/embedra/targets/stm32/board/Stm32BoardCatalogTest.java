package io.github.rezabakhshi.embedra.targets.stm32.board;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.io.AddressRange;
import io.github.rezabakhshi.embedra.targets.stm32.catalog.Stm32CuratedPartIds;
import io.github.rezabakhshi.embedra.targets.stm32.memory.Stm32MemoryPlanner;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;

class Stm32BoardCatalogTest {
    private static final Path ROOT = Path.of("catalogs/stm32/2026-09-29");

    private static final Path SELECTION = ROOT.resolve("selection.json");

    private static final Path PROFILES = ROOT.resolve("board-profiles.json");

    private static final Path PLANS = ROOT.resolve("memory-plans.json");

    private static Stm32BoardCatalog catalog() throws Exception {
        Stm32CuratedPartIds selection = Stm32CuratedPartIds.load(SELECTION,
            ParserLimits.defaults(), CancellationToken.none());
        return Stm32BoardCatalog.load(PROFILES, selection, ParserLimits.defaults(),
            CancellationToken.none());
    }

    @Test
    void loadsDigestPinnedSnapshotWithReviewedAndUnavailableProfiles() throws Exception {
        Stm32BoardCatalog catalog = catalog();
        assertEquals(12, catalog.size());
        assertEquals(9, catalog.profiles().stream()
            .filter(Stm32BoardProfile::reviewed).count());
        assertEquals(3, catalog.profiles().stream()
            .filter(profile -> !profile.reviewed()).count());
    }

    @Test
    void resolvesOnlyExactPartLinksNeverFamilyOrWildcard() throws Exception {
        Stm32BoardCatalog catalog = catalog();
        Stm32BoardProfile h735 = catalog.requireProfiles("STM32H735IGK6");
        assertEquals("STM32H735G-DK", h735.board());
        assertThrows(IllegalArgumentException.class,
            () -> catalog.requireProfiles("STM32H735IGH6"));
        assertThrows(IllegalArgumentException.class,
            () -> catalog.requireProfiles("STM32H73"));
    }

    @Test
    void reviewedProfileCarriesExternalFlashAndRamWithEvidence() throws Exception {
        Stm32BoardProfile h735 = catalog().requireProfiles("STM32H735IGK6");
        assertEquals(0x4000000L, h735.externalFlashBytes());
        assertEquals(0x1000000L, h735.externalRamBytes());
        assertEquals(0x90000000L, h735.externalRegions().get(0).range().start());
        assertTrue(h735.externalRegions().stream()
            .allMatch(region -> !region.startEvidence().isBlank()
                && !region.sizeEvidence().isBlank()));
        assertEquals("4d2e91db442e525b8b879fba260fc3c6369a87d5", h735.bsp().revision());
    }

    @Test
    void unavailableProfileStaysExplicitWithReasonAndNoData() throws Exception {
        Stm32BoardProfile unavailable = catalog().forPart("STM32G473QET6").get(0);
        assertFalse(unavailable.reviewed());
        assertTrue(unavailable.externalRegions().isEmpty());
        assertTrue(unavailable.bootOffsets().isEmpty());
        assertTrue(unavailable.reason().contains("NO_PINNED_BSP"));
    }

    @Test
    void tamperedDigestIsRejected() throws Exception {
        Path tampered = Files.createTempFile("board-profiles", ".json");
        try {
            byte[] bytes = Files.readAllBytes(PROFILES);
            for (int index = 0; index < bytes.length; index++) {
                if (bytes[index] == 'S') {
                    bytes[index] = 'T';
                    break;
                }
            }
            Files.write(tampered, bytes);
            Stm32CuratedPartIds selection = Stm32CuratedPartIds.load(SELECTION,
                ParserLimits.defaults(), CancellationToken.none());
            assertThrows(java.io.IOException.class, () -> Stm32BoardCatalog.load(tampered,
                selection, ParserLimits.defaults(), CancellationToken.none()));
        }
        finally {
            Files.deleteIfExists(tampered);
        }
    }

    @Test
    void composesWithValidatedMcuPlanWithoutMutatingIt() throws Exception {
        Stm32CuratedPartIds selection = Stm32CuratedPartIds.load(SELECTION,
            ParserLimits.defaults(), CancellationToken.none());
        Stm32MemoryPlanner memory = Stm32MemoryPlanner.load(PLANS, selection,
            ParserLimits.defaults(), CancellationToken.none());
        Stm32MemoryPlanner.Plan before = memory.plan("STM32H735IGK6",
            Stm32MemoryPlanner.BootMode.UNKNOWN);
        Stm32BoardPlanner.BoardPlan composed = Stm32BoardPlanner.compose(
            before, catalog().requireProfiles("STM32H735IGK6"));
        assertEquals(0x4000000L, composed.externalFlashBytes());
        assertEquals(0x1000000L, composed.externalRamBytes());
        // The underlying MCU plan is unchanged and still has its own regions.
        assertEquals(before.regions(), composed.mcuPlan().regions());
        assertEquals(before.exactPart(), composed.mcuPlan().exactPart());
    }

    @Test
    void mismatchedPartFailsClosed() throws Exception {
        Stm32CuratedPartIds selection = Stm32CuratedPartIds.load(SELECTION,
            ParserLimits.defaults(), CancellationToken.none());
        Stm32MemoryPlanner memory = Stm32MemoryPlanner.load(PLANS, selection,
            ParserLimits.defaults(), CancellationToken.none());
        Stm32BoardProfile profile = catalog().requireProfiles("STM32H735IGK6");
        Stm32MemoryPlanner.Plan other = memory.plan("STM32F103C8T6",
            Stm32MemoryPlanner.BootMode.UNKNOWN);
        Stm32BoardPlanner.BoardPlanException exception = assertThrows(
            Stm32BoardPlanner.BoardPlanException.class,
            () -> Stm32BoardPlanner.compose(other, profile));
        assertEquals(Stm32BoardPlanner.Diagnostic.BOARD_PART_MISMATCH,
            exception.diagnostic());
    }

    @Test
    void entityAndRegionInvariantsRejectOverlapAndBadAddressSpaces() {
        AddressRange external = new AddressRange("ext-mem", 0x90000000L, 0x1000L);
        assertThrows(IllegalArgumentException.class,
            () -> new AddressRange("ext-mem", 0x90000000L, -1L));
        // A region must use the external-memory address space, not a CPU space.
        assertThrows(IllegalArgumentException.class,
            () -> new Stm32BoardProfile.ExternalRegion("R", Stm32BoardProfile.Kind
                .EXTERNAL_FLASH_MEMORY_MAPPED, "OCTOSPI1", "MX25",
                new AddressRange("ram", 0x90000000L, 0x1000L), true, "s", "z"));
        // Zero-length external regions are rejected.
        assertThrows(IllegalArgumentException.class,
            () -> new Stm32BoardProfile.ExternalRegion("R", Stm32BoardProfile.Kind
                .EXTERNAL_FLASH_MEMORY_MAPPED, "OCTOSPI1", "MX25",
                new AddressRange("ext-mem", 0x90000000L, 0L), true, "s", "z"));
        assertEquals(0x1000L, external.length());
    }

    @Test
    void overlappingExternalRegionsAreRejectedByTheModel() {
        AddressRange first = new AddressRange("ext-mem", 0x90000000L, 0x1000L);
        AddressRange second = new AddressRange("ext-mem", 0x90000800L, 0x1000L);
        Stm32BoardProfile.ExternalRegion left = new Stm32BoardProfile.ExternalRegion("A",
            Stm32BoardProfile.Kind.EXTERNAL_FLASH_MEMORY_MAPPED, "OCTOSPI1", "MX25",
            first, true, "s", "z");
        Stm32BoardProfile.ExternalRegion right = new Stm32BoardProfile.ExternalRegion("B",
            Stm32BoardProfile.Kind.EXTERNAL_RAM_MEMORY_MAPPED, "QSPI", "PSRAM",
            second, true, "s", "z");
        Stm32BoardProfile.BoardSource source = new Stm32BoardProfile.BoardSource(
            "boards/x.ioc", "0".repeat(64));
        Stm32BoardProfile.BoardBsp bsp = new Stm32BoardProfile.BoardBsp(
            "stm32h735g-dk-bsp", "a".repeat(40), "note");
        assertThrows(IllegalArgumentException.class, () -> new Stm32BoardProfile(
            "B", "Discovery", "STM32H735IGK6",
            Stm32BoardProfile.Status.EXTERNAL_MEMORY_REVIEWED, source, bsp, "cmsis-device-h7",
            List.of(left, right), List.of(), null));
    }
}
