package io.github.rezabakhshi.embedra.core.catalog;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.targets.esp.catalog.EspCatalogEntityKind;
import io.github.rezabakhshi.embedra.targets.esp.catalog.EspCatalogRecord;
import io.github.rezabakhshi.embedra.targets.esp.catalog.EspCpuIsa;
import io.github.rezabakhshi.embedra.targets.esp.catalog.EspDeviceCatalog;
import io.github.rezabakhshi.embedra.targets.esp.catalog.EspDeviceCatalogLoader;
import io.github.rezabakhshi.embedra.targets.rp.catalog.RpBoardProfile;
import io.github.rezabakhshi.embedra.targets.rp.catalog.RpDeviceCatalog;
import io.github.rezabakhshi.embedra.targets.rp.catalog.RpDeviceCatalogLoader;
import io.github.rezabakhshi.embedra.targets.rp.catalog.RpSiliconRecord;
import io.github.rezabakhshi.embedra.targets.stm32.catalog.Stm32CuratedPartIds;
import io.github.rezabakhshi.embedra.targets.stm32.catalog.Stm32DevicePackRegistry;
import io.github.rezabakhshi.embedra.targets.stm32.catalog.Stm32SvdApplicability;
import io.github.rezabakhshi.embedra.targets.stm32.memory.Stm32MemoryPlanner;
import io.github.rezabakhshi.embedra.targets.stm32.mp.Stm32MpProviderRegistry;
import io.github.rezabakhshi.embedra.targets.stm32.mp.Stm32MpTargetProvider;
import io.github.rezabakhshi.embedra.targets.stm32.security.Stm32SecurityCatalog;
import io.github.rezabakhshi.embedra.targets.stm32.security.Stm32SecurityRecord;
import io.github.rezabakhshi.embedra.targets.stm32.wireless.Stm32WirelessPlanner;
import io.github.rezabakhshi.embedra.targets.stm32.wireless.Stm32WirelessRecord;
import io.github.rezabakhshi.embedra.targets.stm32.workspace.Stm32WorkspacePlan;
import io.github.rezabakhshi.embedra.targets.stm32.workspace.Stm32WorkspacePlanner;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;

/**
 * Master verification suite for T074: ESP and Raspberry Pi discovery completeness and drift,
 * and exact support state and execution topology for every selected STM32 catalog part.
 */
class CatalogDiscoveryAndExecutionTopologyMasterSuiteTest {

    private static final Path ESP_CATALOG_DIR = Path.of("catalogs", "espressif", "2026-09-23");

    private static final Path RP_CATALOG_DIR = Path.of("catalogs", "rp", "2026-10-02");

    private static final Path STM32_DIR = Path.of("catalogs", "stm32", "2026-09-29");

    private static final Path STM32_SELECTION = STM32_DIR.resolve("selection.json");

    private static final Path STM32_CATALOG = STM32_DIR.resolve("curated-catalog.json");

    private static final Path STM32_SECURITY = STM32_DIR.resolve("security-domains.json");

    private static final Set<String> EXPECTED_ESP_SERIES = Set.of(
        "ESP32", "ESP32-S2", "ESP32-S3", "ESP32-S31", "ESP32-P4", "ESP32-C2",
        "ESP32-C3", "ESP32-C5", "ESP32-C6", "ESP32-C61", "ESP32-E22",
        "ESP32-H2", "ESP32-H21", "ESP32-H4"
    );

    @Test
    void testEspDiscoveryCompletenessAndDriftContract() throws Exception {
        EspDeviceCatalog catalog = EspDeviceCatalogLoader.load(
            ESP_CATALOG_DIR, ParserLimits.defaults(), CancellationToken.none());

        assertEquals(53, catalog.silicon().size());
        assertEquals(161, catalog.modules().size());
        assertEquals(58, catalog.boards().size());

        Set<String> discoveredSeries = catalog.silicon().stream()
            .map(EspCatalogRecord::series)
            .collect(Collectors.toSet());
        assertEquals(EXPECTED_ESP_SERIES, discoveredSeries);

        // Every silicon record starts in PLANNED support state for all capabilities
        assertTrue(catalog.silicon().stream().allMatch(record ->
            record.supportStates().values().stream().allMatch(state -> state == SupportState.PLANNED)));

        // Provenance revision must match source facts digest
        assertEquals(catalog.sourceFactsSha256(), catalog.deviceSnapshot().source().revision());

        // Legacy ESP8266 must remain strictly segregated from modern ESP discovery
        assertFalse(catalog.records().stream()
            .anyMatch(record -> record.exactPart().startsWith("ESP8266")));

        // Profile integrity: modules and boards must map exclusively to valid silicon
        Set<String> siliconRecordIds = catalog.silicon().stream()
            .map(EspCatalogRecord::recordId)
            .collect(Collectors.toSet());
        assertTrue(catalog.modules().stream().allMatch(module ->
            !module.siliconRecordIds().isEmpty() && siliconRecordIds.containsAll(module.siliconRecordIds())));
        assertTrue(catalog.boards().stream().allMatch(board ->
            !board.siliconRecordIds().isEmpty() && siliconRecordIds.containsAll(board.siliconRecordIds())));

        // Execution topologies across all series
        for (EspCatalogRecord record : catalog.silicon()) {
            assertEquals(EspCatalogEntityKind.SILICON, record.kind());
            switch (record.series()) {
                case "ESP32", "ESP32-S3" -> {
                    assertEquals(EspCpuIsa.XTENSA, record.isa());
                    assertEquals(2, record.applicationCoreCount());
                }
                case "ESP32-S2" -> {
                    assertEquals(EspCpuIsa.XTENSA, record.isa());
                    assertEquals(1, record.applicationCoreCount());
                }
                case "ESP32-P4", "ESP32-S31", "ESP32-E22", "ESP32-H4" -> {
                    assertEquals(EspCpuIsa.RISCV, record.isa());
                    assertEquals(2, record.applicationCoreCount());
                }
                case "ESP32-C2", "ESP32-C3", "ESP32-C5", "ESP32-C6", "ESP32-C61",
                     "ESP32-H2", "ESP32-H21" -> {
                    assertEquals(EspCpuIsa.RISCV, record.isa());
                    assertEquals(1, record.applicationCoreCount());
                }
                default -> throw new AssertionError("Unexpected series: " + record.series());
            }
        }
    }

    @Test
    void testRaspberryPiDiscoveryCompletenessAndDriftContract() throws Exception {
        RpDeviceCatalog catalog = RpDeviceCatalogLoader.load(
            RP_CATALOG_DIR, ParserLimits.defaults(), CancellationToken.none());

        assertNotNull(catalog);
        assertEquals(5, catalog.siliconRecords().size());
        assertEquals(4, catalog.boardProfiles().size());

        Set<String> siliconParts = catalog.siliconRecords().stream()
            .map(RpSiliconRecord::exactPart)
            .collect(Collectors.toSet());
        assertEquals(Set.of("RP2040", "RP2350A", "RP2350B", "RP2354A", "RP2354B"), siliconParts);

        // Every silicon part and board profile begins in PLANNED state per RP-002
        assertTrue(catalog.siliconRecords().stream()
            .allMatch(record -> record.supportState() == SupportState.PLANNED));
        assertTrue(catalog.boardProfiles().stream()
            .allMatch(board -> board.supportState() == SupportState.PLANNED));

        // RP2040 exact topology
        RpSiliconRecord rp2040 = catalog.requireExactPart("RP2040");
        assertEquals("QFN-56", rp2040.packageName());
        assertEquals(30, rp2040.gpioCount());
        assertEquals(264 * 1024, rp2040.sramBytes());
        assertEquals(0, rp2040.internalFlashBytes());
        assertEquals(16 * 1024 * 1024, rp2040.externalXipLimitBytes());
        assertEquals(2, rp2040.pioBlocks());
        assertEquals(8, rp2040.totalPioStateMachines());
        assertEquals(List.of("ARM_CORTEX_M0P"), rp2040.bootArchitectures());
        assertTrue(rp2040.supportsArm());
        assertFalse(rp2040.supportsRiscV());
        assertFalse(rp2040.hasInternalFlash());

        // RP2350A vs RP2350B execution topology and packaging
        RpSiliconRecord rp2350a = catalog.requireExactPart("RP2350A");
        RpSiliconRecord rp2350b = catalog.requireExactPart("RP2350B");
        assertEquals("QFN-60", rp2350a.packageName());
        assertEquals(30, rp2350a.gpioCount());
        assertEquals("QFN-80", rp2350b.packageName());
        assertEquals(48, rp2350b.gpioCount());
        assertEquals(520 * 1024, rp2350a.sramBytes());
        assertEquals(520 * 1024, rp2350b.sramBytes());
        assertEquals(0, rp2350a.internalFlashBytes());
        assertEquals(0, rp2350b.internalFlashBytes());
        assertEquals(3, rp2350a.pioBlocks());
        assertEquals(12, rp2350a.totalPioStateMachines());
        assertTrue(rp2350a.supportsArm());
        assertTrue(rp2350a.supportsRiscV());
        assertTrue(rp2350a.securityCapabilities().contains("ARM_TRUSTZONE"));
        assertTrue(rp2350a.securityCapabilities().contains("OTP_8KB"));

        // RP2354 stacked internal flash topology
        RpSiliconRecord rp2354a = catalog.requireExactPart("RP2354A");
        RpSiliconRecord rp2354b = catalog.requireExactPart("RP2354B");
        assertTrue(rp2354a.hasInternalFlash());
        assertTrue(rp2354b.hasInternalFlash());
        assertEquals(2 * 1024 * 1024, rp2354a.internalFlashBytes());
        assertEquals(2 * 1024 * 1024, rp2354b.internalFlashBytes());
        assertEquals("QFN-60", rp2354a.packageName());
        assertEquals("QFN-80", rp2354b.packageName());

        // Board profile validation
        RpBoardProfile pico = catalog.requireBoardProfile("pico");
        assertEquals("RP2040", pico.siliconPart());
        assertEquals(2 * 1024 * 1024, pico.externalFlashBytes());
        assertFalse(pico.hasWireless());
        assertNull(pico.wirelessChip());

        RpBoardProfile picoW = catalog.requireBoardProfile("pico_w");
        assertEquals("RP2040", picoW.siliconPart());
        assertTrue(picoW.hasWireless());
        assertEquals("Infineon CYW43439", picoW.wirelessChip().model());

        RpBoardProfile pico2 = catalog.requireBoardProfile("pico2");
        assertEquals("RP2350A", pico2.siliconPart());
        assertEquals(4 * 1024 * 1024, pico2.externalFlashBytes());
        assertFalse(pico2.hasWireless());

        RpBoardProfile pico2W = catalog.requireBoardProfile("pico2_w");
        assertEquals("RP2350A", pico2W.siliconPart());
        assertEquals(4 * 1024 * 1024, pico2W.externalFlashBytes());
        assertTrue(pico2W.hasWireless());
        assertEquals("Infineon CYW43439", pico2W.wirelessChip().model());
    }

    @Test
    void testStm32ExactFiftyThreePartsSelectionAndAntiDriftContract() throws Exception {
        Stm32CuratedPartIds ids = Stm32CuratedPartIds.load(
            STM32_SELECTION, ParserLimits.defaults(), CancellationToken.none());
        Stm32DevicePackRegistry registry = Stm32DevicePackRegistry.load(
            STM32_CATALOG, ids, ParserLimits.defaults(), CancellationToken.none());

        assertEquals(53, ids.size());
        assertEquals(53, registry.size());
        assertEquals(20, registry.families().size());

        // Anti-drift: All 53 parts must have supportState PLANNED and packStatus CATALOG_ONLY
        for (Stm32DevicePackRegistry.Part part : registry.parts()) {
            assertEquals("PLANNED", part.supportState());
            assertEquals("CATALOG_ONLY", part.packStatus());
            assertFalse(part.exactPart().contains("*"));
            assertFalse(part.exactPart().contains("?"));
        }

        // Silent expansion prevention: wildcards, bare family names, lowercase throw IllegalArgumentException
        assertThrows(IllegalArgumentException.class, () -> registry.selectExact("STM32F103*"));
        assertThrows(IllegalArgumentException.class, () -> registry.selectExact("STM32F103"));
        assertThrows(IllegalArgumentException.class, () -> registry.selectExact("stm32f103c8t6"));
        assertThrows(IllegalArgumentException.class, () -> registry.selectExact("STM32H7*"));
        assertThrows(IllegalArgumentException.class, () -> registry.selectExact("UNKNOWN_PART"));

        // Exact parts select cleanly
        Stm32DevicePackRegistry.Part f103c8 = registry.selectExact("STM32F103C8T6");
        assertEquals("STM32F103C8T6", f103c8.exactPart());
        assertEquals("STM32F103", f103c8.family());
        assertEquals("LQFP48", f103c8.packageName());
        assertEquals(64, f103c8.flashKiB().orElseThrow());

        // Curated selection digest verification
        assertEquals("1d4b971f0264815492bf644552b8c83abf0393b627216a89640080b8ccf8b3b4",
            Stm32CuratedPartIds.SELECTION_SHA256);
        assertEquals("afc66a47cd79c2025d115049c8aebd2db671c1112d42531b1db50df8514858f9",
            Stm32DevicePackRegistry.CATALOG_SHA256);
    }

    @Test
    void testStm32ExecutionTopologyAndCoreDistributionForEverySelectedPart() throws Exception {
        Stm32CuratedPartIds ids = Stm32CuratedPartIds.load(
            STM32_SELECTION, ParserLimits.defaults(), CancellationToken.none());
        Stm32DevicePackRegistry registry = Stm32DevicePackRegistry.load(
            STM32_CATALOG, ids, ParserLimits.defaults(), CancellationToken.none());

        Map<String, Integer> coreCounts = new HashMap<>();
        for (Stm32DevicePackRegistry.Part part : registry.parts()) {
            for (String core : part.cores()) {
                coreCounts.put(core, coreCounts.getOrDefault(core, 0) + 1);
            }
        }

        // Exact core topology verification across all 53 parts
        assertEquals(13, coreCounts.get("ARM Cortex-M0+").intValue());
        assertEquals(4, coreCounts.get("ARM Cortex-M3").intValue());
        assertEquals(11, coreCounts.get("ARM Cortex-M4").intValue());
        assertEquals(5, coreCounts.get("ARM Cortex-M7").intValue());
        assertEquals(19, coreCounts.get("ARM Cortex-M33").intValue());
        assertEquals(1, coreCounts.get("ARM Cortex-M55").intValue());

        // Flagship high-performance parts
        Stm32DevicePackRegistry.Part h735 = registry.selectExact("STM32H735IGK6");
        assertEquals(List.of("ARM Cortex-M7"), h735.cores());

        Stm32DevicePackRegistry.Part f401 = registry.selectExact("STM32F401RET6");
        assertEquals(List.of("ARM Cortex-M4"), f401.cores());

        // Cortex-M55 flagship part
        Stm32DevicePackRegistry.Part n6 = registry.selectExact("STM32N657X0H3Q");
        assertEquals(List.of("ARM Cortex-M55"), n6.cores());
        assertEquals(0, n6.flashKiB().orElseThrow());
    }

    @Test
    void testStm32AdvancedExecutionTopologyVerification() throws Exception {
        Stm32CuratedPartIds ids = Stm32CuratedPartIds.load(
            STM32_SELECTION, ParserLimits.defaults(), CancellationToken.none());
        Stm32SecurityCatalog securityCatalog = Stm32SecurityCatalog.load(
            STM32_SECURITY, ids, ParserLimits.defaults(), CancellationToken.none());

        // Exactly 19 parts with pinned TrustZone alias view apertures (L5, U5, H5, WBA)
        assertEquals(53, securityCatalog.size());
        assertEquals(19, securityCatalog.aliasViewParts());
        assertEquals(34, securityCatalog.unavailableParts());

        Stm32SecurityRecord l552 = securityCatalog.requireRecord("STM32L552ZET6Q");
        assertTrue(l552.pinned());
        assertFalse(l552.windows().isEmpty());

        // Non-TrustZone parts have empty windows and pinned false
        Stm32SecurityRecord h503 = securityCatalog.requireRecord("STM32H503RBT6");
        assertFalse(h503.pinned());
        assertTrue(h503.windows().isEmpty());

        // Wireless subsystem verification
        Stm32MemoryPlanner memoryPlanner = Stm32MemoryPlanner.load(
            STM32_DIR.resolve("memory-plans.json"), ids, ParserLimits.defaults(), CancellationToken.none());
        Stm32SvdApplicability svdApplicability = Stm32SvdApplicability.load(
            STM32_DIR.resolve("svd-applicability.json"), ids, ParserLimits.defaults(), CancellationToken.none());
        Stm32DevicePackRegistry registry = Stm32DevicePackRegistry.load(
            STM32_CATALOG, ids, ParserLimits.defaults(), CancellationToken.none());

        Stm32DevicePackRegistry.Part wb55Part = registry.selectExact("STM32WB55RGV6");
        Stm32MemoryPlanner.Plan wb55Plan = memoryPlanner.plan("STM32WB55RGV6", Stm32MemoryPlanner.BootMode.UNKNOWN);
        Stm32SecurityRecord wb55Security = securityCatalog.requireRecord("STM32WB55RGV6");
        Stm32WorkspacePlan wb55Workspace = Stm32WorkspacePlanner.compose(wb55Plan, wb55Security);
        Stm32SvdApplicability.Entry wb55Entry = svdApplicability.requireEntry("STM32WB55RGV6");

        Stm32WirelessRecord wb55Record = Stm32WirelessPlanner.compose(
            wb55Part, wb55Plan, wb55Workspace, wb55Security, wb55Entry);
        assertTrue(wb55Record.pinnedNetworkCore());
        assertEquals(Stm32WirelessRecord.Series.WB, wb55Record.series());

        // STM32MP application processor separation (MP1 / MP2 are not in pure MCU catalog)
        Stm32MpProviderRegistry mpRegistry = Stm32MpProviderRegistry.instance();
        Optional<Stm32MpTargetProvider> mp157 = mpRegistry.findByExactPart("STM32MP157C");
        assertTrue(mp157.isPresent());
        assertEquals("STM32MP1", mp157.get().family());
        assertFalse(ids.containsExactPart("STM32MP157C"));

        Optional<Stm32MpTargetProvider> mp257 = mpRegistry.findByExactPart("STM32MP257F");
        assertTrue(mp257.isPresent());
        assertEquals("STM32MP2", mp257.get().family());
        assertFalse(ids.containsExactPart("STM32MP257F"));
    }
}
