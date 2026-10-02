package io.github.rezabakhshi.embedra.targets.stm32.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.targets.stm32.catalog.Stm32CuratedPartIds;
import io.github.rezabakhshi.embedra.targets.stm32.memory.Stm32MemoryPlanner;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class Stm32SecurityPlannerTest {
    private static final Path ROOT = Path.of("catalogs/stm32/2026-09-29");

    private static final String HEADER_SHA256 =
        "c2ac14f09cc63e53d9eed5605038b7590d753f12fa3ace8d2ab209582d120f25";

    private static Stm32CuratedPartIds selection() throws Exception {
        return Stm32CuratedPartIds.load(ROOT.resolve("selection.json"),
            ParserLimits.defaults(), CancellationToken.none());
    }

    private static Stm32MemoryPlanner memory() throws Exception {
        return Stm32MemoryPlanner.load(ROOT.resolve("memory-plans.json"), selection(),
            ParserLimits.defaults(), CancellationToken.none());
    }

    private static Stm32SecurityCatalog security() throws Exception {
        return Stm32SecurityCatalog.load(ROOT.resolve("security-domains.json"), selection(),
            ParserLimits.defaults(), CancellationToken.none());
    }

    private static Stm32SecurityHeaderSource header() {
        return new Stm32SecurityHeaderSource(
            "https://github.com/STMicroelectronics/cmsis-device-l5",
            "e237398c0cbae890f4659f74fe6b64cae339b6a0", "Include/stm32l552xx.h",
            HEADER_SHA256, "Apache-2.0");
    }

    private static Stm32SecurityWindow secureWindow(String id, long start, long size,
            List<String> aliases) {
        return new Stm32SecurityWindow(id, Stm32SecurityWindow.Kind.FLASH,
            Stm32SecurityAttribute.SECURE, Stm32SecurityWindow.BoundaryKind.ALIAS_APERTURE,
            start, size, "FLASH", aliases, "FLASH_BASE_S", 1511,
            "(0x0C000000UL) /*!< FLASH secure base address */", "Include/stm32l552xx.h",
            Stm32SecurityWindow.PartitionState.UNRESOLVED_CONFIGURATION_DEPENDENT);
    }

    private static Stm32SecurityWindow nscWindow(String id, long start, long size) {
        return new Stm32SecurityWindow(id, Stm32SecurityWindow.Kind.FLASH,
            Stm32SecurityAttribute.NON_SECURE_CALLABLE,
            Stm32SecurityWindow.BoundaryKind.PARTITION, start, size, "FLASH",
            List.of(), "FLASH_SECWM1R1", 7529, "FLASH_SECWM1R1_SECWM1_PEND",
            "Include/stm32l552xx.h",
            Stm32SecurityWindow.PartitionState.UNRESOLVED_CONFIGURATION_DEPENDENT);
    }

    private static Stm32SecurityRecord record(Stm32SecurityWindow... windows) {
        return new Stm32SecurityRecord("STM32L552ZET6Q",
            Stm32SecurityRecord.Status.ALIAS_VIEWS_PINNED, null, List.of(header()),
            List.of(windows), List.of(),
            new Stm32SecurityRecord.NscBoundary(
                Stm32SecurityRecord.EvidenceState.UNAVAILABLE, "NO_PINNED_NSC", List.of()),
            new Stm32SecurityRecord.VeneerEvidence(
                Stm32SecurityRecord.EvidenceState.UNAVAILABLE, "NO_PINNED_NSC", null,
                List.of()));
    }

    @Test
    void composesPinnedRecordWithValidatedPlanWithoutMutation() throws Exception {
        Stm32MemoryPlanner memory = memory();
        Stm32MemoryPlanner.Plan before = memory.plan("STM32L552ZET6Q",
            Stm32MemoryPlanner.BootMode.UNKNOWN);
        Stm32SecurityRecord l552 = security().requireRecord("STM32L552ZET6Q");
        Stm32SecurityPlanner.SecurityMap map = Stm32SecurityPlanner.compose(before, l552);
        assertEquals(3, map.regions().size());
        assertEquals(before.regions(), map.mcuPlan().regions());
        assertEquals(before.aliases(), map.mcuPlan().aliases());
        Stm32SecurityPlanner.SecurityRegion flash = map.regions().stream()
            .filter(region -> region.windowId().equals("FLASH_S"))
            .findFirst()
            .orElseThrow();
        assertEquals(0x0C000000L, flash.range().start());
        assertEquals(0x80000L, flash.range().length());
        assertEquals(Stm32SecurityAttribute.SECURE, flash.attribute());
        assertEquals(Stm32SecurityWindow.PartitionState.UNRESOLVED_CONFIGURATION_DEPENDENT,
            flash.partitionState());
        assertEquals(-1L, flash.secureBytes());
        assertFalse(map.partitionResolved());
        assertTrue(map.veneerTransitions().isEmpty());
        assertEquals("PLANNED", map.supportState());
    }

    @Test
    void configurationInputResolvesOnlyTheNamedSecurePartition() throws Exception {
        Stm32MemoryPlanner.Plan plan = memory().plan("STM32L552ZET6Q",
            Stm32MemoryPlanner.BootMode.UNKNOWN);
        Stm32SecurityRecord l552 = security().requireRecord("STM32L552ZET6Q");
        Stm32SecurityPlanner.SecurityMap map = Stm32SecurityPlanner.compose(plan, l552,
            Map.of("FLASH_S", 0x40000L));
        Stm32SecurityPlanner.SecurityRegion flash = map.regions().stream()
            .filter(region -> region.windowId().equals("FLASH_S"))
            .findFirst()
            .orElseThrow();
        assertEquals(Stm32SecurityWindow.PartitionState.CONFIGURATION_INPUT,
            flash.partitionState());
        assertEquals(0x40000L, flash.secureBytes());
        assertFalse(map.partitionResolved());
        Stm32SecurityPlanner.SecurityMap resolved = Stm32SecurityPlanner.compose(plan, l552,
            Map.of("FLASH_S", 0x40000L, "SRAM1_S", 0x10000L, "SRAM2_S", 0x8000L));
        assertTrue(resolved.partitionResolved());
    }

    @Test
    void unknownConfigurationKeyFailsClosed() throws Exception {
        Stm32MemoryPlanner.Plan plan = memory().plan("STM32L552ZET6Q",
            Stm32MemoryPlanner.BootMode.UNKNOWN);
        Stm32SecurityRecord l552 = security().requireRecord("STM32L552ZET6Q");
        Stm32SecurityPlanner.SecurityPlanException exception = assertThrows(
            Stm32SecurityPlanner.SecurityPlanException.class,
            () -> Stm32SecurityPlanner.compose(plan, l552, Map.of("NOT_A_WINDOW", 16L)));
        assertEquals(Stm32SecurityPlanner.Diagnostic.SECURITY_CONFIGURATION_UNKNOWN,
            exception.diagnostic());
    }

    @Test
    void outOfRangeConfigurationFailsClosed() throws Exception {
        Stm32MemoryPlanner.Plan plan = memory().plan("STM32L552ZET6Q",
            Stm32MemoryPlanner.BootMode.UNKNOWN);
        Stm32SecurityRecord l552 = security().requireRecord("STM32L552ZET6Q");
        for (long size : new long[] {0L, 0x80001L}) {
            Stm32SecurityPlanner.SecurityPlanException exception = assertThrows(
                Stm32SecurityPlanner.SecurityPlanException.class,
                () -> Stm32SecurityPlanner.compose(plan, l552, Map.of("FLASH_S", size)));
            assertEquals(Stm32SecurityPlanner.Diagnostic.SECURITY_CONFIGURATION_OUT_OF_RANGE,
                exception.diagnostic());
        }
    }

    @Test
    void configurationOnNonSecureCallableBoundaryIsNotApplicable() throws Exception {
        Stm32SecurityRecord synthetic = record(
            secureWindow("FLASH_S", 0x0C000000L, 0x80000L, List.of("FLASH_SECURE_VIEW")),
            nscWindow("NSC_FLASH", 0x0C040000L, 0x100L));
        Stm32MemoryPlanner.Plan plan = memory().plan("STM32L552ZET6Q",
            Stm32MemoryPlanner.BootMode.UNKNOWN);
        Stm32SecurityPlanner.SecurityPlanException exception = assertThrows(
            Stm32SecurityPlanner.SecurityPlanException.class,
            () -> Stm32SecurityPlanner.compose(plan, synthetic, Map.of("NSC_FLASH", 0x100L)));
        assertEquals(Stm32SecurityPlanner.Diagnostic.SECURITY_CONFIGURATION_NOT_APPLICABLE,
            exception.diagnostic());
    }

    @Test
    void partMismatchAndUnavailablePartFailClosed() throws Exception {
        Stm32MemoryPlanner memory = memory();
        Stm32SecurityRecord l552 = security().requireRecord("STM32L552ZET6Q");
        Stm32MemoryPlanner.Plan f103 = memory.plan("STM32F103C8T6",
            Stm32MemoryPlanner.BootMode.UNKNOWN);
        Stm32SecurityPlanner.SecurityPlanException mismatch = assertThrows(
            Stm32SecurityPlanner.SecurityPlanException.class,
            () -> Stm32SecurityPlanner.compose(f103, l552));
        assertEquals(Stm32SecurityPlanner.Diagnostic.SECURITY_PART_MISMATCH,
            mismatch.diagnostic());
        Stm32MemoryPlanner.Plan c031 = memory.plan("STM32C031C6T3",
            Stm32MemoryPlanner.BootMode.UNKNOWN);
        Stm32SecurityRecord unavailable = security().requireRecord("STM32C031C6T3");
        Stm32SecurityPlanner.SecurityPlanException notAvailable = assertThrows(
            Stm32SecurityPlanner.SecurityPlanException.class,
            () -> Stm32SecurityPlanner.compose(c031, unavailable));
        assertEquals(Stm32SecurityPlanner.Diagnostic.SECURITY_NOT_AVAILABLE,
            notAvailable.diagnostic());
    }

    @Test
    void overlappingAndMismatchedWindowsFailClosed() throws Exception {
        Stm32MemoryPlanner.Plan plan = memory().plan("STM32L552ZET6Q",
            Stm32MemoryPlanner.BootMode.UNKNOWN);
        Stm32SecurityRecord overlap = record(
            secureWindow("FLASH_S", 0x08000000L, 0x80000L, List.of("FLASH_SECURE_VIEW")));
        assertEquals(Stm32SecurityPlanner.Diagnostic.SECURITY_WINDOW_OVERLAP,
            assertThrows(Stm32SecurityPlanner.SecurityPlanException.class,
                () -> Stm32SecurityPlanner.compose(plan, overlap)).diagnostic());
        Stm32SecurityRecord smaller = record(
            secureWindow("FLASH_S", 0x0C000000L, 0x40000L, List.of("FLASH_SECURE_VIEW")));
        assertEquals(Stm32SecurityPlanner.Diagnostic.SECURITY_WINDOW_RANGE_MISMATCH,
            assertThrows(Stm32SecurityPlanner.SecurityPlanException.class,
                () -> Stm32SecurityPlanner.compose(plan, smaller)).diagnostic());
        Stm32SecurityRecord unpaired = record(
            secureWindow("FLASH_S", 0x0C000000L, 0x80000L, List.of("NOT_AN_ALIAS")));
        assertEquals(Stm32SecurityPlanner.Diagnostic.SECURITY_WINDOW_UNPAIRED,
            assertThrows(Stm32SecurityPlanner.SecurityPlanException.class,
                () -> Stm32SecurityPlanner.compose(plan, unpaired)).diagnostic());
    }

    @Test
    void modelRejectsOverlappingAperturesAndUncoveredVeneers() {
        Stm32SecurityWindow first = secureWindow("A", 0x0C000000L, 0x80000L,
            List.of("FLASH_SECURE_VIEW"));
        Stm32SecurityWindow second = secureWindow("B", 0x0C040000L, 0x80000L,
            List.of("FLASH_SECURE_VIEW"));
        assertThrows(IllegalArgumentException.class, () -> record(first, second));
        Stm32SecurityWindow nsc = nscWindow("NSC", 0x08000000L, 0x100L);
        assertThrows(IllegalArgumentException.class, () -> record(nsc));
        assertThrows(IllegalArgumentException.class, () -> new Stm32SecurityWindow("X",
            Stm32SecurityWindow.Kind.RAM, Stm32SecurityAttribute.NON_SECURE_CALLABLE,
            Stm32SecurityWindow.BoundaryKind.ALIAS_APERTURE, 0x20000000L, 0x100L, "SRAM1",
            List.of(), "SRAM1_BASE_S", 1, "decl", "Include/x.h",
            Stm32SecurityWindow.PartitionState.UNRESOLVED_CONFIGURATION_DEPENDENT));
    }
}
