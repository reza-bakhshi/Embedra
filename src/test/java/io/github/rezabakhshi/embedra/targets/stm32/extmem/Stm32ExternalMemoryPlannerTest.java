package io.github.rezabakhshi.embedra.targets.stm32.extmem;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.core.io.AddressRange;
import io.github.rezabakhshi.embedra.core.model.Evidence;
import io.github.rezabakhshi.embedra.core.model.EvidenceKind;
import io.github.rezabakhshi.embedra.targets.stm32.board.Stm32BoardCatalog;
import io.github.rezabakhshi.embedra.targets.stm32.board.Stm32BoardProfile;
import io.github.rezabakhshi.embedra.targets.stm32.catalog.Stm32DevicePackRegistry;
import io.github.rezabakhshi.embedra.targets.stm32.extmem.Stm32ExternalMemoryPlan.ControllerFamily;
import io.github.rezabakhshi.embedra.targets.stm32.extmem.Stm32ExternalMemoryPlan.MappingWindow;
import io.github.rezabakhshi.embedra.targets.stm32.extmem.Stm32ExternalMemoryPlan.Source;
import io.github.rezabakhshi.embedra.targets.stm32.extmem.Stm32ExternalMemoryPlan.Status;
import io.github.rezabakhshi.embedra.targets.stm32.extmem.Stm32ExternalMemoryPlanner.Diagnostic;
import io.github.rezabakhshi.embedra.targets.stm32.extmem.Stm32ExternalMemoryPlanner
    .ExternalMemoryPlanException;
import io.github.rezabakhshi.embedra.targets.stm32.extmem.Stm32ExternalMemoryPlanner
    .Stm32ExternalMemoryLoadPlan;
import io.github.rezabakhshi.embedra.targets.stm32.memory.Stm32MemoryPlanner;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** Composition, load-planning, and fail-closed tests over the pinned T042 profiles. */
class Stm32ExternalMemoryPlannerTest {
    private static final Path ROOT = Path.of("catalogs/stm32/2026-09-29");

    private static final Path SELECTION = ROOT.resolve("selection.json");

    private static final Path PROFILES = ROOT.resolve("board-profiles.json");

    private static final Path PLANS = ROOT.resolve("memory-plans.json");

    private static final Path CATALOG = ROOT.resolve("curated-catalog.json");

    private static final String H735 = "STM32H735IGK6";

    @Test
    void composesH735WindowsFromThePinnedBoardProfileAndPlan() throws Exception {
        Loads loads = loads();
        Stm32MemoryPlanner.Plan mcu = loads.memory().plan(H735,
            Stm32MemoryPlanner.BootMode.UNKNOWN);
        Stm32ExternalMemoryPlan plan = Stm32ExternalMemoryPlanner.compose(mcu,
            loads.boards().requireProfiles(H735));

        assertEquals(Status.EXTERNAL_MEMORY_MAPPED, plan.status());
        assertNull(plan.reason());
        assertEquals(Source.PINNED_T042_BOARD_PROFILE, plan.source());
        assertEquals("STM32H735G-DK", plan.board());
        assertEquals(H735, plan.exactPart());
        assertEquals("PLANNED", plan.supportState());
        assertTrue(plan.mapped());
        assertSame(mcu, plan.mcuPlan());
        assertEquals(mcu.regions(), plan.mcuPlan().regions());

        assertEquals(2, plan.windows().size());
        MappingWindow nor = plan.windows().get(0);
        assertEquals("OSPI2_RAM", nor.id());
        assertEquals(0x70000000L, nor.mappedRange().start());
        assertEquals("ext-mem", nor.mappedRange().addressSpace());
        assertEquals(0x1000000L, nor.mappedRange().length());
        assertEquals("S70KL1281", nor.device());
        assertEquals("OCTOSPI2", nor.controller());
        assertEquals(ControllerFamily.OCTOSPI, nor.controllerFamily());
        assertEquals(Stm32BoardProfile.Kind.EXTERNAL_RAM_MEMORY_MAPPED, nor.kind());
        assertTrue(nor.writable());
        MappingWindow flash = plan.windows().get(1);
        assertEquals("OSPI1_NOR", flash.id());
        assertEquals(0x90000000L, flash.mappedRange().start());
        assertEquals(0x4000000L, flash.mappedRange().length());
        assertEquals("MX25LM51245G", flash.device());
        assertEquals("OCTOSPI1", flash.controller());
        assertEquals(ControllerFamily.OCTOSPI, flash.controllerFamily());
        assertEquals(Stm32BoardProfile.Kind.EXTERNAL_FLASH_MEMORY_MAPPED, flash.kind());
        assertTrue(flash.writable());
        assertTrue(flash.startEvidence().contains("OCTOSPI1_BASE"));
        assertTrue(flash.sizeEvidence().contains("MX25LM51245G_FLASH_SIZE"));

        Set<String> digests = new LinkedHashSet<>();
        for (Evidence entry : plan.evidence()) {
            digests.add(entry.source().substring(entry.source().lastIndexOf(':') + 1));
        }
        assertTrue(digests.contains("78a3e0e41cc14585ad3c4140aed80fff6d53fcd367d6beec3d2cc787950c75f3"));
        assertTrue(digests.contains("00def2817ba0660644a4bc6cea3ffb756e11aff4d7236a466f82de838c280c66"));
        assertTrue(plan.evidence().stream()
            .allMatch(entry -> entry.kind() == EvidenceKind.VERIFIED_CHECKSUM));
    }

    @Test
    void apertureAndDeviceOffsetTranslationsStayExact() throws Exception {
        MappingWindow window = h735Windows().get(1);
        assertEquals(0x4000000L, window.mappedRange().length());
        assertTrue(window.coversDeviceOffset(0L));
        assertTrue(window.coversDeviceOffset(0x3FFFFFFL));
        assertFalse(window.coversDeviceOffset(0x4000000L));
        assertFalse(window.coversDeviceOffset(-1L));
        assertTrue(window.coversCpuAddress(0x90000000L));
        assertTrue(window.coversCpuAddress(0x93FFFFFFL));
        assertFalse(window.coversCpuAddress(0x94000000L));
        assertFalse(window.coversCpuAddress(0x8FFFFFFFL));
        assertEquals(0x90000000L, window.cpuAddressOfDeviceOffset(0L));
        assertEquals(0x90001000L, window.cpuAddressOfDeviceOffset(0x1000L));
        assertEquals(0x93FFFFFFL, window.cpuAddressOfDeviceOffset(0x3FFFFFFL));
        assertEquals(0x1000L, window.deviceOffsetOfCpuAddress(0x90001000L));
        assertEquals(0x3FFFFFFL, window.deviceOffsetOfCpuAddress(0x93FFFFFFL));
        assertThrows(IllegalArgumentException.class,
            () -> window.cpuAddressOfDeviceOffset(0x4000000L));
        assertThrows(IllegalArgumentException.class,
            () -> window.cpuAddressOfDeviceOffset(-1L));
        assertThrows(IllegalArgumentException.class,
            () -> window.deviceOffsetOfCpuAddress(0x94000000L));
        assertThrows(IllegalArgumentException.class,
            () -> window.deviceOffsetOfCpuAddress(0x70000000L));
    }

    @Test
    void controllerFamilyProjectionIsMechanicalAndFailsClosed() {
        assertEquals(ControllerFamily.OCTOSPI, ControllerFamily.of("OCTOSPI1"));
        assertEquals(ControllerFamily.OCTOSPI, ControllerFamily.of("OCTOSPI2"));
        assertEquals(ControllerFamily.XSPI, ControllerFamily.of("XSPI2"));
        assertEquals(ControllerFamily.QUADSPI, ControllerFamily.of("QUADSPI"));
        assertEquals(ControllerFamily.FMC, ControllerFamily.of("FMC_SDRAM_BANK2"));
        assertThrows(IllegalArgumentException.class, () -> ControllerFamily.of("MY_CTRL"));
        assertThrows(NullPointerException.class, () -> ControllerFamily.of(null));
    }

    @Test
    void classifyCpuAddressMapsOnlyPinnedWindows() throws Exception {
        Stm32ExternalMemoryPlan plan = h735Plan();
        Stm32ExternalMemoryPlanner.MappedAddress nor =
            Stm32ExternalMemoryPlanner.classifyCpuAddress(plan, 0x90001000L);
        assertEquals("OSPI1_NOR", nor.deviceId());
        assertEquals("OCTOSPI1", nor.controller());
        assertEquals(ControllerFamily.OCTOSPI, nor.controllerFamily());
        assertEquals(0x1000L, nor.deviceOffset());
        assertTrue(nor.writable());
        Stm32ExternalMemoryPlanner.MappedAddress ram =
            Stm32ExternalMemoryPlanner.classifyCpuAddress(plan, 0x70000000L);
        assertEquals("OSPI2_RAM", ram.deviceId());
        ExternalMemoryPlanException uncovered = assertThrows(ExternalMemoryPlanException.class,
            () -> Stm32ExternalMemoryPlanner.classifyCpuAddress(plan, 0x20000000L));
        assertEquals(Diagnostic.LOADER_ADDRESS_UNCOVERED, uncovered.diagnostic());
    }

    @Test
    void planLoadProducesExactPlacementWithPinnedPermissions() throws Exception {
        Stm32ExternalMemoryPlan plan = h735Plan();
        Stm32ExternalMemoryLoadPlan load = Stm32ExternalMemoryPlanner.planLoad(plan,
            "OSPI1_NOR", 0x1000L, 0x200L, ParserLimits.defaults());
        assertEquals(H735, load.exactPart());
        assertEquals("OSPI1_NOR", load.deviceId());
        assertEquals(Stm32BoardProfile.Kind.EXTERNAL_FLASH_MEMORY_MAPPED, load.kind());
        assertEquals("OCTOSPI1", load.controller());
        assertEquals(ControllerFamily.OCTOSPI, load.controllerFamily());
        assertEquals(0x1000L, load.deviceOffset());
        assertEquals(0x200L, load.length());
        assertEquals(0x90001000L, load.cpuAddress());
        assertTrue(load.writable());
        assertEquals(new AddressRange("ext-mem", 0x90000000L, 0x4000000L), load.window());
        assertEquals(Source.PINNED_T042_BOARD_PROFILE, load.source());
        assertFalse(load.evidence().isEmpty());
        assertTrue(load.evidence().stream().anyMatch(entry ->
            entry.kind() == EvidenceKind.DOCUMENTED_FIELD
                && entry.source().equals("stm32.extmem:window:OSPI1_NOR")));

        Stm32ExternalMemoryLoadPlan ram = Stm32ExternalMemoryPlanner.planLoad(plan,
            "OSPI2_RAM", 0L, 8L, ParserLimits.defaults());
        assertEquals(0x70000000L, ram.cpuAddress());
        assertTrue(ram.writable());
        assertEquals(Source.PINNED_T042_BOARD_PROFILE, ram.source());
    }

    @Test
    void planLoadFailsClosedOnEveryBadInput() throws Exception {
        Loads loads = loads();
        Stm32MemoryPlanner.Plan f103 = loads.memory().plan("STM32F103C8T6",
            Stm32MemoryPlanner.BootMode.UNKNOWN);
        Stm32ExternalMemoryPlan unavailable = Stm32ExternalMemoryPlanner.compose(f103,
            loads.boards());
        assertTrue(unavailable.reason().contains("NO_CONFIRMED_BOARD_PROFILE"));
        ExternalMemoryPlanException notAvailable = assertThrows(
            ExternalMemoryPlanException.class,
            () -> Stm32ExternalMemoryPlanner.planLoad(unavailable, "OSPI1_NOR", 0L, 8L,
                ParserLimits.defaults()));
        assertEquals(Diagnostic.LOADER_NOT_AVAILABLE, notAvailable.diagnostic());

        Stm32ExternalMemoryPlan plan = h735Plan();
        ExternalMemoryPlanException unknown = assertThrows(ExternalMemoryPlanException.class,
            () -> Stm32ExternalMemoryPlanner.planLoad(plan, "OSPI3_NOR", 0L, 8L,
                ParserLimits.defaults()));
        assertEquals(Diagnostic.LOADER_DEVICE_UNKNOWN, unknown.diagnostic());
        ExternalMemoryPlanException empty = assertThrows(ExternalMemoryPlanException.class,
            () -> Stm32ExternalMemoryPlanner.planLoad(plan, "OSPI1_NOR", 0L, 0L,
                ParserLimits.defaults()));
        assertEquals(Diagnostic.LOADER_RANGE_EMPTY, empty.diagnostic());
        ExternalMemoryPlanException overflow = assertThrows(ExternalMemoryPlanException.class,
            () -> Stm32ExternalMemoryPlanner.planLoad(plan, "OSPI1_NOR", 0x3FFFFF00L, 0x200L,
                ParserLimits.defaults()));
        assertEquals(Diagnostic.LOADER_RANGE_OVERFLOW, overflow.diagnostic());
        ExternalMemoryPlanException negative = assertThrows(ExternalMemoryPlanException.class,
            () -> Stm32ExternalMemoryPlanner.planLoad(plan, "OSPI1_NOR", -1L, 8L,
                ParserLimits.defaults()));
        assertEquals(Diagnostic.LOADER_RANGE_OVERFLOW, negative.diagnostic());
        ParserLimits tight = new ParserLimits(256, 16, 64, 1_000_000, 32,
            java.time.Duration.ofSeconds(30));
        ExternalMemoryPlanException tooLarge = assertThrows(ExternalMemoryPlanException.class,
            () -> Stm32ExternalMemoryPlanner.planLoad(plan, "OSPI1_NOR", 0L, 65L, tight));
        assertEquals(Diagnostic.LOADER_RANGE_BEYOND_LIMITS, tooLarge.diagnostic());
    }

    @Test
    void everyCuratedPartResolvesExplicitlyFromThePinnedCatalog() throws Exception {
        Loads loads = loads();
        int mapped = 0;
        int pinnedUnavailable = 0;
        int noProfile = 0;
        for (String part : curatedParts(loads)) {
            Stm32MemoryPlanner.Plan mcu = loads.memory().plan(part,
                Stm32MemoryPlanner.BootMode.UNKNOWN);
            Stm32ExternalMemoryPlan plan = Stm32ExternalMemoryPlanner.compose(mcu,
                loads.boards());
            assertEquals("PLANNED", plan.supportState(), part);
            assertEquals(part, plan.exactPart(), part);
            assertSame(mcu, plan.mcuPlan(), part);
            if (plan.mapped()) {
                assertEquals(Source.PINNED_T042_BOARD_PROFILE, plan.source(), part);
                assertFalse(plan.board().isBlank(), part);
                assertFalse(plan.windows().isEmpty(), part);
                mapped++;
            }
            else {
                assertNull(plan.source(), part);
                assertNull(plan.board(), part);
                assertTrue(plan.windows().isEmpty(), part);
                assertTrue(plan.bootOffsets().isEmpty(), part);
                switch (part) {
                    case "STM32G473QET6" -> assertEquals("NO_PINNED_BSP_EXTERNAL_MEMORY_FACT",
                        plan.reason(), part);
                    case "STM32U083MCT6" -> assertEquals(
                        "BOARD_HAS_NO_EXTERNAL_MEMORY_IN_PINNED_BSP", plan.reason(), part);
                    case "STM32L552ZET6Q" -> assertEquals(
                        "BOTH_EXTERNAL_DEVICES_SHARE_OCTOSPI1_MAPPED_WINDOW",
                        plan.reason(), part);
                    default -> assertTrue(plan.reason().startsWith("NO_CONFIRMED_BOARD_PROFILE"),
                        part);
                }
                if (plan.reason().startsWith("NO_CONFIRMED_BOARD_PROFILE")) {
                    noProfile++;
                }
                else {
                    pinnedUnavailable++;
                }
            }
        }
        assertEquals(9, mapped);
        assertEquals(3, pinnedUnavailable);
        assertEquals(41, noProfile);
        assertEquals(53, mapped + pinnedUnavailable + noProfile);
    }

    @Test
    void windowDisjointnessAndPartBindingFailClosed() throws Exception {
        Loads loads = loads();
        Stm32MemoryPlanner.Plan f103 = loads.memory().plan("STM32F103C8T6",
            Stm32MemoryPlanner.BootMode.UNKNOWN);
        Stm32BoardProfile h735 = loads.boards().requireProfiles(H735);
        ExternalMemoryPlanException mismatch = assertThrows(ExternalMemoryPlanException.class,
            () -> Stm32ExternalMemoryPlanner.compose(f103, h735));
        assertEquals(Diagnostic.EXTERNAL_PART_MISMATCH, mismatch.diagnostic());

        Stm32MemoryPlanner.Plan mcu = loads.memory().plan(H735,
            Stm32MemoryPlanner.BootMode.UNKNOWN);
        Stm32ExternalMemoryPlan plan = Stm32ExternalMemoryPlanner.compose(mcu, h735);
        // Windows are numerically disjoint and unique inside the composed plan.
        Set<Long> starts = new LinkedHashSet<>();
        for (MappingWindow window : plan.windows()) {
            assertTrue(starts.add(window.mappedRange().start()));
        }
        // The reused T042 ExternalRegion contract keeps the ext-mem space mandatory.
        assertThrows(IllegalArgumentException.class,
            () -> new Stm32BoardProfile.ExternalRegion("R",
                Stm32BoardProfile.Kind.EXTERNAL_FLASH_MEMORY_MAPPED, "OCTOSPI1", "MX25",
                new AddressRange("ram", 0x90000000L, 0x1000L), true, "s", "z"));
        assertThrows(IllegalArgumentException.class,
            () -> new Stm32ExternalMemoryPlan.MappingWindow("W",
                Stm32BoardProfile.Kind.EXTERNAL_FLASH_MEMORY_MAPPED, "MX25", "OCTOSPI1",
                ControllerFamily.OCTOSPI, new AddressRange("ext-mem", 0x90000000L, 0L), true,
                "s", "z"));
        assertThrows(IllegalArgumentException.class,
            () -> new Stm32ExternalMemoryPlan.MappingWindow("W",
                Stm32BoardProfile.Kind.EXTERNAL_FLASH_MEMORY_MAPPED, "MX25", "OCTOSPI1",
                ControllerFamily.OCTOSPI,
                new AddressRange("ext-mem", 0xFFFFFFF0L, 0x20L), true, "s", "z"));
        assertThrows(IllegalArgumentException.class,
            () -> new Stm32ExternalMemoryPlan.MappingWindow("W",
                Stm32BoardProfile.Kind.EXTERNAL_FLASH_MEMORY_MAPPED, "MX25", "OCTOSPI1",
                ControllerFamily.OCTOSPI, new AddressRange("ext-mem", 0x90000000L, 0x1000L),
                true, " ", "z"));
    }

    @Test
    void confirmedCustomProfilesComposeWithoutTouchingPinnedSnapshots() throws Exception {
        Loads loads = loads();
        Stm32MemoryPlanner.Plan h7s3 = loads.memory().plan("STM32H7S3L8H6",
            Stm32MemoryPlanner.BootMode.UNKNOWN);
        assertTrue(loads.boards().forPart("STM32H7S3L8H6").isEmpty());
        Stm32CustomBoardProfile custom = new Stm32CustomBoardProfile("custom-xspi-board",
            "STM32H7S3L8H6",
            List.of(new Stm32BoardProfile.ExternalRegion("CUSTOM_NOR",
                Stm32BoardProfile.Kind.EXTERNAL_FLASH_MEMORY_MAPPED, "XSPI2", "MX25LM51245G",
                new AddressRange("ext-mem", 0x70000000L, 0x800000L), true,
                "user-confirmed XSPI2 mapping", "user-confirmed 8 MiB NOR")),
            List.of(), userAssertion());
        Stm32ExternalMemoryPlan plan = Stm32ExternalMemoryPlanner.composeConfirmed(h7s3,
            custom);
        assertEquals(Status.EXTERNAL_MEMORY_MAPPED, plan.status());
        assertEquals(Source.CONFIRMED_CUSTOM_PROFILE, plan.source());
        assertEquals("custom-xspi-board", plan.board());
        assertEquals(1, plan.windows().size());
        assertEquals("CUSTOM_NOR", plan.windows().get(0).id());
        assertEquals(ControllerFamily.XSPI, plan.windows().get(0).controllerFamily());
        assertEquals(0x70000000L, plan.windows().get(0).mappedRange().start());
        assertTrue(plan.evidence().stream()
            .anyMatch(entry -> entry.kind() == EvidenceKind.USER_ASSERTION));
        // The pinned catalog is untouched: L552 stays explicitly unavailable and
        // H735 still composes exactly its two pinned windows.
        Stm32MemoryPlanner.Plan l552 = loads.memory().plan("STM32L552ZET6Q",
            Stm32MemoryPlanner.BootMode.UNKNOWN);
        assertEquals("BOTH_EXTERNAL_DEVICES_SHARE_OCTOSPI1_MAPPED_WINDOW",
            Stm32ExternalMemoryPlanner.compose(l552, loads.boards()).reason());
        Stm32ExternalMemoryPlan pinned = Stm32ExternalMemoryPlanner.compose(
            loads.memory().plan(H735, Stm32MemoryPlanner.BootMode.UNKNOWN),
            loads.boards().requireProfiles(H735));
        assertEquals(2, pinned.windows().size());
    }

    @Test
    void customProfilesFailClosedOnFabricatedOrOverlappingData() throws Exception {
        Loads loads = loads();
        Stm32MemoryPlanner.Plan mcu = loads.memory().plan(H735,
            Stm32MemoryPlanner.BootMode.UNKNOWN);

        assertThrows(NullPointerException.class, () -> new Stm32CustomBoardProfile(
            "custom", H735, List.of(region("R", 0x90000000L, 0x1000L, true)), List.of(),
            null));
        assertThrows(IllegalArgumentException.class, () -> new Stm32CustomBoardProfile(
            "custom", H735, List.of(region("R", 0x90000000L, 0x1000L, true)), List.of(),
            new Evidence(EvidenceKind.VERIFIED_CHECKSUM, "s", "d")));
        assertThrows(IllegalArgumentException.class, () -> new Stm32CustomBoardProfile(
            " ", H735, List.of(region("R", 0x90000000L, 0x1000L, true)), List.of(),
            userAssertion()));
        assertThrows(IllegalArgumentException.class, () -> new Stm32CustomBoardProfile(
            "custom", H735, List.of(), List.of(), userAssertion()));
        assertThrows(IllegalArgumentException.class, () -> new Stm32CustomBoardProfile(
            "custom", H735,
            List.of(region("R", 0x90000000L, 0x1000L, true),
                region("R", 0x70000000L, 0x1000L, true)),
            List.of(), userAssertion()));
        assertThrows(IllegalArgumentException.class, () -> new Stm32CustomBoardProfile(
            "custom", H735,
            List.of(region("R", 0x90000000L, 0x1000L, true),
                region("R2", 0x90000800L, 0x1000L, true)),
            List.of(), userAssertion()));

        // A fabricated controller is rejected, not invented around.
        Stm32CustomBoardProfile unknownController = new Stm32CustomBoardProfile("custom",
            H735, List.of(new Stm32BoardProfile.ExternalRegion("R",
                Stm32BoardProfile.Kind.EXTERNAL_RAM_MEMORY_MAPPED, "MY_CTRL", "PSRAM",
                new AddressRange("ext-mem", 0x60000000L, 0x1000L), true, "u", "u")),
            List.of(), userAssertion());
        ExternalMemoryPlanException controller = assertThrows(
            ExternalMemoryPlanException.class,
            () -> Stm32ExternalMemoryPlanner.composeConfirmed(mcu, unknownController));
        assertEquals(Diagnostic.EXTERNAL_CONTROLLER_UNRECOGNIZED, controller.diagnostic());

        // An overlap with a pinned MCU region fails closed.
        Stm32CustomBoardProfile overlapping = new Stm32CustomBoardProfile("custom", H735,
            List.of(region("R", 0x08000000L, 0x1000L, true)), List.of(), userAssertion());
        ExternalMemoryPlanException mcuOverlap = assertThrows(
            ExternalMemoryPlanException.class,
            () -> Stm32ExternalMemoryPlanner.composeConfirmed(mcu, overlapping));
        assertEquals(Diagnostic.EXTERNAL_WINDOW_OVERLAPS_MCU, mcuOverlap.diagnostic());

        // A window beyond the 32-bit space fails closed.
        Stm32CustomBoardProfile oversized = new Stm32CustomBoardProfile("custom", H735,
            List.of(new Stm32BoardProfile.ExternalRegion("R",
                Stm32BoardProfile.Kind.EXTERNAL_RAM_MEMORY_MAPPED, "OCTOSPI1", "PSRAM",
                new AddressRange("ext-mem", 0xFFFFFFF0L, 0x20L), true, "u", "u")),
            List.of(), userAssertion());
        ExternalMemoryPlanException outOfSpace = assertThrows(
            ExternalMemoryPlanException.class,
            () -> Stm32ExternalMemoryPlanner.composeConfirmed(mcu, oversized));
        assertEquals(Diagnostic.EXTERNAL_WINDOW_OUT_OF_SPACE, outOfSpace.diagnostic());

        // A boot offset outside every external region fails closed.
        Stm32CustomBoardProfile badBoot = new Stm32CustomBoardProfile("custom", H735,
            List.of(region("R", 0x90000000L, 0x1000L, true)),
            List.of(new Stm32BoardProfile.BootOffset("B", "image start", 0x70000000L)),
            userAssertion());
        ExternalMemoryPlanException boot = assertThrows(ExternalMemoryPlanException.class,
            () -> Stm32ExternalMemoryPlanner.composeConfirmed(mcu, badBoot));
        assertEquals(Diagnostic.EXTERNAL_BOOT_OFFSET_OUT_OF_RANGE, boot.diagnostic());

        // A mismatched custom part fails closed.
        Stm32CustomBoardProfile wrongPart = new Stm32CustomBoardProfile("custom",
            "STM32F103C8T6", List.of(region("R", 0x90000000L, 0x1000L, true)), List.of(),
            userAssertion());
        ExternalMemoryPlanException mismatch = assertThrows(ExternalMemoryPlanException.class,
            () -> Stm32ExternalMemoryPlanner.composeConfirmed(mcu, wrongPart));
        assertEquals(Diagnostic.EXTERNAL_PART_MISMATCH, mismatch.diagnostic());
    }

    @Test
    void customProfileLoaderFailsClosedOnMalformedAndOutOfRangeInput() throws Exception {
        Loads loads = loads();
        var limits = ParserLimits.defaults();
        var token = CancellationToken.none();
        Path good = Path.of(System.getProperty("java.io.tmpdir"), "embedra-custom-good.json");
        Files.write(good, customProfileJson().getBytes(java.nio.charset.StandardCharsets.UTF_8));
        try {
            Stm32CustomBoardProfile profile = Stm32CustomBoardProfile.load(good, loads.ids(),
                limits, token);
            assertEquals("STM32H7S3L8H6", profile.exactPart());
            assertEquals(1, profile.externalRegions().size());
            assertEquals("CUSTOM_NOR", profile.externalRegions().get(0).id());
            assertEquals(EvidenceKind.USER_ASSERTION, profile.confirmation().kind());
        }
        finally {
            Files.deleteIfExists(good);
        }

        assertCustomProfileRejected(loads, limits, token, "schema-mismatch",
            customProfileJson(CUSTOM_CONFIRMATION, "STM32H7S3L8H6",
                "EXTERNAL_FLASH_MEMORY_MAPPED", "8388608").replace(CUSTOM_SCHEMA,
                "urn:embedra:schema:something-else:1"));
        assertCustomProfileRejected(loads, limits, token, "missing-confirmation-field",
            customProfileJson("", "STM32H7S3L8H6", "EXTERNAL_FLASH_MEMORY_MAPPED", "8388608"));
        assertCustomProfileRejected(loads, limits, token, "extra-root-field",
            customProfileJson(CUSTOM_CONFIRMATION, "STM32H7S3L8H6",
                "EXTERNAL_FLASH_MEMORY_MAPPED", "8388608").replace("\"bootOffsets\": []",
                "\"bootOffsets\": [], \"invented\": true"));
        assertCustomProfileRejected(loads, limits, token, "unknown-kind",
            customProfileJson(CUSTOM_CONFIRMATION, "STM32H7S3L8H6", "FABRICATED_MEMORY",
                "8388608"));
        assertCustomProfileRejected(loads, limits, token, "non-integer-size",
            customProfileJson(CUSTOM_CONFIRMATION, "STM32H7S3L8H6",
                "EXTERNAL_FLASH_MEMORY_MAPPED", "\"8 MiB\""));
        assertCustomProfileRejected(loads, limits, token, "non-curated-part",
            customProfileJson(CUSTOM_CONFIRMATION, "STM32FAKE0000",
                "EXTERNAL_FLASH_MEMORY_MAPPED", "8388608"));

        byte[] truncated = new byte[customProfileJson().length() - 12];
        System.arraycopy(customProfileJson().getBytes(java.nio.charset.StandardCharsets.UTF_8),
            0, truncated, 0, truncated.length);
        Path cut = Path.of(System.getProperty("java.io.tmpdir"), "embedra-custom-cut.json");
        Files.write(cut, truncated);
        try {
            assertThrows(DiagnosticException.class, () -> Stm32CustomBoardProfile.load(cut,
                loads.ids(), limits, token));
        }
        finally {
            Files.deleteIfExists(cut);
        }

        byte[] padded = new byte[customProfileJson().length() + 4096];
        System.arraycopy(customProfileJson().getBytes(java.nio.charset.StandardCharsets.UTF_8),
            0, padded, 0, customProfileJson().length());
        padded[customProfileJson().length()] = '\n';
        ParserLimits tight = new ParserLimits(256, 16, 512, 1_000_000, 32,
            java.time.Duration.ofSeconds(30));
        Path huge = Path.of(System.getProperty("java.io.tmpdir"), "embedra-custom-huge.json");
        Files.write(huge, padded);
        try {
            assertThrows(IOException.class, () -> Stm32CustomBoardProfile.load(huge,
                loads.ids(), tight, token));
        }
        finally {
            Files.deleteIfExists(huge);
        }
    }

    private static void assertCustomProfileRejected(Loads loads, ParserLimits limits,
            CancellationToken token, String label, String json) throws IOException {
        Path path = Path.of(System.getProperty("java.io.tmpdir"), "embedra-custom-" + label
            + ".json");
        Files.write(path, json.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        try {
            assertThrows(IOException.class, () -> Stm32CustomBoardProfile.load(path,
                loads.ids(), limits, token), label);
        }
        finally {
            Files.deleteIfExists(path);
        }
    }

    @Test
    void compositionIsDeterministicAndImmutabilityHolds() throws Exception {
        Loads first = loads();
        Loads second = loads();
        Stm32ExternalMemoryPlan one = Stm32ExternalMemoryPlanner.compose(
            first.memory().plan(H735, Stm32MemoryPlanner.BootMode.UNKNOWN),
            first.boards().requireProfiles(H735));
        Stm32ExternalMemoryPlan two = Stm32ExternalMemoryPlanner.compose(
            second.memory().plan(H735, Stm32MemoryPlanner.BootMode.UNKNOWN),
            second.boards().requireProfiles(H735));
        assertEquals(one, two);
        assertNotSame(one.windows(), two.windows());
        assertThrows(UnsupportedOperationException.class,
            () -> one.windows().add(one.windows().get(0)));
        assertThrows(UnsupportedOperationException.class,
            () -> one.evidence().clear());
        // The MCU plan object is held, not rebuilt or mutated.
        Stm32MemoryPlanner.Plan mcu = first.memory().plan(H735,
            Stm32MemoryPlanner.BootMode.UNKNOWN);
        assertSame(mcu,
            Stm32ExternalMemoryPlanner.compose(mcu, first.boards().requireProfiles(H735))
                .mcuPlan());
    }

    private record Loads(Stm32MemoryPlanner memory, Stm32BoardCatalog boards,
            Stm32DevicePackRegistry registry,
            io.github.rezabakhshi.embedra.targets.stm32.catalog.Stm32CuratedPartIds ids) {
    }

    private static Loads loads() throws IOException, DiagnosticException {
        var limits = ParserLimits.defaults();
        var token = CancellationToken.none();
        var ids = io.github.rezabakhshi.embedra.targets.stm32.catalog.Stm32CuratedPartIds
            .load(SELECTION, limits, token);
        return new Loads(
            Stm32MemoryPlanner.load(PLANS, ids, limits, token),
            Stm32BoardCatalog.load(PROFILES, ids, limits, token),
            Stm32DevicePackRegistry.load(CATALOG, ids, limits, token), ids);
    }

    private static Stm32ExternalMemoryPlan h735Plan() throws Exception {
        Loads loads = loads();
        return Stm32ExternalMemoryPlanner.compose(
            loads.memory().plan(H735, Stm32MemoryPlanner.BootMode.UNKNOWN),
            loads.boards().requireProfiles(H735));
    }

    private static List<MappingWindow> h735Windows() throws Exception {
        return h735Plan().windows();
    }

    private static List<String> curatedParts(Loads loads) {
        return loads.registry().parts().stream()
            .map(Stm32DevicePackRegistry.Part::exactPart)
            .sorted()
            .toList();
    }

    private static Evidence userAssertion() {
        return new Evidence(EvidenceKind.USER_ASSERTION, "user-confirmed-board-note",
            "The user confirmed every fact of this custom profile from their own board");
    }

    private static Stm32BoardProfile.ExternalRegion region(String id, long start, long size,
            boolean writable) {
        return new Stm32BoardProfile.ExternalRegion(id,
            Stm32BoardProfile.Kind.EXTERNAL_RAM_MEMORY_MAPPED, "OCTOSPI1", "PSRAM",
            new AddressRange("ext-mem", start, size), writable, "user start evidence",
            "user size evidence");
    }

    private static final String CUSTOM_SCHEMA =
        "urn:embedra:schema:stm32-custom-board-profile:1";

    private static final String CUSTOM_CONFIRMATION = "  \"confirmation\": {\n"
        + "    \"source\": \"user-confirmed-board-note\",\n"
        + "    \"detail\": \"The user confirmed every fact of this custom profile from "
            + "their own board\"\n"
        + "  },\n";

    private static String customProfileJson() {
        return customProfileJson(CUSTOM_CONFIRMATION, "STM32H7S3L8H6",
            "EXTERNAL_FLASH_MEMORY_MAPPED", "8388608");
    }

    private static String customProfileJson(String confirmationBlock, String exactPart,
            String kind, String size) {
        return "{\n"
            + "  \"$schema\": \"" + CUSTOM_SCHEMA + "\",\n"
            + "  \"board\": \"custom-xspi-board\",\n"
            + "  \"exactPart\": \"" + exactPart + "\",\n"
            + confirmationBlock
            + "  \"externalRegions\": [\n"
            + "    {\n"
            + "      \"id\": \"CUSTOM_NOR\",\n"
            + "      \"kind\": \"" + kind + "\",\n"
            + "      \"controller\": \"XSPI2\",\n"
            + "      \"device\": \"MX25LM51245G\",\n"
            + "      \"start\": 1879048192,\n"
            + "      \"size\": " + size + ",\n"
            + "      \"writable\": true,\n"
            + "      \"startEvidence\": \"user-confirmed XSPI2 mapping\",\n"
            + "      \"sizeEvidence\": \"user-confirmed 8 MiB NOR\"\n"
            + "    }\n"
            + "  ],\n"
            + "  \"bootOffsets\": []\n"
            + "}\n";
    }
}
