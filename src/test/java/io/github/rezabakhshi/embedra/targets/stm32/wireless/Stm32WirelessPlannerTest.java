package io.github.rezabakhshi.embedra.targets.stm32.wireless;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.core.io.AddressRange;
import io.github.rezabakhshi.embedra.pack.StrictJsonParser;
import io.github.rezabakhshi.embedra.targets.stm32.catalog.Stm32CuratedPartIds;
import io.github.rezabakhshi.embedra.targets.stm32.catalog.Stm32DevicePackRegistry;
import io.github.rezabakhshi.embedra.targets.stm32.catalog.Stm32SvdApplicability;
import io.github.rezabakhshi.embedra.targets.stm32.memory.Stm32MemoryPlanner;
import io.github.rezabakhshi.embedra.targets.stm32.security.Stm32SecurityCatalog;
import io.github.rezabakhshi.embedra.targets.stm32.security.Stm32SecurityRecord;
import io.github.rezabakhshi.embedra.targets.stm32.workspace.Stm32WorkspacePlan;
import io.github.rezabakhshi.embedra.targets.stm32.workspace.Stm32WorkspacePlanner;
import io.github.rezabakhshi.embedra.targets.stm32.wireless.Stm32WirelessRecord.Series;
import io.github.rezabakhshi.embedra.targets.stm32.wireless.Stm32WirelessRecord.Status;
import io.github.rezabakhshi.embedra.targets.stm32.wireless.Stm32WirelessPlanner.Diagnostic;
import io.github.rezabakhshi.embedra.targets.stm32.wireless.Stm32WirelessPlanner.NetworkCoreImageBinding;
import io.github.rezabakhshi.embedra.targets.stm32.wireless.Stm32WirelessPlanner.WirelessPlanException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** Composition, binding, and fail-closed regression tests on pinned catalogs. */
class Stm32WirelessPlannerTest {
    private static final Path SELECTION = Path.of("catalogs/stm32/2026-09-29/selection.json");

    private static final Path CATALOG = Path.of("catalogs/stm32/2026-09-29/curated-catalog.json");

    private static final Path MEMORY_PLANS = Path.of("catalogs/stm32/2026-09-29/memory-plans.json");

    private static final Path SECURITY_DOMAINS =
        Path.of("catalogs/stm32/2026-09-29/security-domains.json");

    private static final Path SVD_APPLICABILITY =
        Path.of("catalogs/stm32/2026-09-29/svd-applicability.json");

    private static final List<String> WIRELESS_SCOPE = List.of(
        "STM32WBA25CEU7", "STM32WBA52CGU6", "STM32WBA65RIV7", "STM32WB05KZV6TR",
        "STM32WB07CCV6TR", "STM32WB09KEV6TR", "STM32WB15CCU6", "STM32WB55RGV6",
        "STM32WL33CCV6TR", "STM32WL3RKBV6");

    @Test
    void wb55PinsTheNetworkCoreWithPerCoreRegisterModelsAndWindows() throws Exception {
        Composed composed = compose("STM32WB55RGV6");
        Stm32WirelessRecord record = composed.record();
        assertTrue(record.pinnedNetworkCore());
        assertEquals(Status.NETWORK_CORE_PINNED, record.status());
        assertEquals(Series.WB, record.series());
        assertEquals("PLANNED", record.supportState());

        assertEquals("cpu1", record.applicationCore().nodeId());
        assertEquals("Application Cortex-M4", record.applicationCore().role());
        assertEquals(Stm32WirelessRecord.RegisterModel.SHIPPED,
            record.applicationCore().registerModel());
        assertNull(record.applicationCore().registerModelReason());
        assertEquals("STM32WB55_CM4", record.applicationCore().svdFile().deviceName());
        assertEquals("stm32wb/STM32WB55_CM4.svd", record.applicationCore().svdFile().path());

        assertEquals("cpu2", record.networkCore().core().nodeId());
        assertEquals("Network Cortex-M0+", record.networkCore().core().role());
        assertEquals(Stm32WirelessRecord.RegisterModel.SHIPPED,
            record.networkCore().core().registerModel());
        assertEquals("STM32WB55_CM0P", record.networkCore().core().svdFile().deviceName());
        assertEquals(Stm32WirelessRecord.CoprocessorFirmware.State.INDEPENDENTLY_SUPPLIED,
            record.networkCore().firmware().state());
        assertEquals(Stm32WirelessRecord.CoprocessorFirmware.Binding
            .UNRESOLVED_CONFIGURATION_DEPENDENT, record.networkCore().firmware().binding());
        assertTrue(record.networkCore().firmware().bindingMechanism().contains("C2BOOT"));
        assertEquals("cpu2-fetch-view", record.networkCore().firmware().fetchView().id());
        assertTrue(record.networkCore().firmware().fetchView().reason()
            .contains("configuration"));
        assertEquals(Set.of(new AddressRange("peripheral", 0x58000C00L, 0x400L),
            new AddressRange("peripheral", 0x58001400L, 0x400L)),
            Set.copyOf(record.networkCore().communicationRanges()));

        assertEquals(Stm32WirelessRecord.Management.NETWORK_CORE_MANAGED,
            record.radioSubsystem().management());
        assertEquals(Stm32WirelessRecord.RegisterModel.UNAVAILABLE,
            record.radioSubsystem().registerModel());
        assertEquals("RADIO_REGISTERS_NOT_IN_PINNED_REGISTER_MODELS",
            record.radioSubsystem().registerModelReason());

        assertSame(composed.inputs().workspace(), record.sharedResources().workspace());
        assertSame(composed.inputs().securityRecord(), record.securityRecord());
        assertFalse(record.securityRecord().pinned());
        assertEquals(Stm32WirelessRecord.SharedResources.State
            .SHARED_RESOURCES_IN_PINNED_WORKSPACE_PLAN, record.sharedResources().state());
        Set<String> digests = new LinkedHashSet<>();
        for (var evidence : record.evidence()) {
            digests.add(evidence.source().substring(evidence.source().lastIndexOf(':') + 1));
        }
        assertEquals(Set.of(
            "afc66a47cd79c2025d115049c8aebd2db671c1112d42531b1db50df8514858f9",
            "00def2817ba0660644a4bc6cea3ffb756e11aff4d7236a466f82de838c280c66",
            "08da45f506d670df3ed042243513d0a3751d07cce2b256cb2c46cd7db23ee3e9",
            "be795ab0d0d5da1b218428361690753fb39e8f962b3de8c160ae9a43d7970518"), digests);
        assertSame(composed.inputs().workspace().mcuPlan(), composed.inputs().plan());
        assertEquals(Stm32SecurityRecord.Status.UNAVAILABLE,
            composed.inputs().securityRecord().status());
    }

    @Test
    void wb15PinsItsNetworkCoreAndKeepsTheAbsentCm0pLineExplicit() throws Exception {
        Stm32WirelessRecord record = compose("STM32WB15CCU6").record();
        assertTrue(record.pinnedNetworkCore());
        assertEquals(Series.WB, record.series());
        assertEquals(Stm32WirelessRecord.RegisterModel.DEFERRED,
            record.applicationCore().registerModel());
        assertEquals("STM32WB15_CM4", record.applicationCore().svdFile().deviceName());
        assertEquals("DUAL_CORE_M4_SVD_AVAILABLE_M0P_DEVICE_LINE_ABSENT",
            record.applicationCore().registerModelReason());
        assertEquals(Stm32WirelessRecord.RegisterModel.UNAVAILABLE,
            record.networkCore().core().registerModel());
        assertEquals("DUAL_CORE_M4_SVD_AVAILABLE_M0P_DEVICE_LINE_ABSENT",
            record.networkCore().core().registerModelReason());
        assertNull(record.networkCore().core().svdFile());
        assertEquals(2, record.networkCore().communicationRanges().size());
        assertEquals("RADIO_REGISTERS_DEFERRED_WITH_THE_DEVICE_LINE",
            record.radioSubsystem().registerModelReason());
        assertEquals(Stm32WirelessRecord.Management.NETWORK_CORE_MANAGED,
            record.radioSubsystem().management());
        assertEquals(Stm32WirelessRecord.SharedResources.State
            .SHARED_RESOURCES_IN_PINNED_WORKSPACE_PLAN, record.sharedResources().state());
    }

    @Test
    void everyWirelessScopePartIsClassifiedFromPinnedData() throws Exception {
        SeededLoads loads = loaders();
        int pinnedNetworkCores = 0;
        int singleApplicationCores = 0;
        for (String part : WIRELESS_SCOPE) {
            Stm32WirelessRecord record = compose(composeInputs(loads, part));
            assertEquals("PLANNED", record.supportState(), part);
            switch (part) {
                case "STM32WB55RGV6", "STM32WB15CCU6" -> {
                    assertEquals(Status.NETWORK_CORE_PINNED, record.status(), part);
                    assertEquals(Series.WB, record.series(), part);
                    pinnedNetworkCores++;
                }
                case "STM32WB05KZV6TR", "STM32WB07CCV6TR", "STM32WB09KEV6TR" -> {
                    assertEquals(Status.SINGLE_APPLICATION_CORE, record.status(), part);
                    assertEquals(Series.WB0, record.series(), part);
                    singleApplicationCores++;
                }
                case "STM32WBA25CEU7", "STM32WBA52CGU6", "STM32WBA65RIV7" -> {
                    assertEquals(Status.SINGLE_APPLICATION_CORE, record.status(), part);
                    assertEquals(Series.WBA, record.series(), part);
                    singleApplicationCores++;
                    assertTrue(record.securityRecord().pinned(), part);
                }
                case "STM32WL33CCV6TR", "STM32WL3RKBV6" -> {
                    assertEquals(Status.SINGLE_APPLICATION_CORE, record.status(), part);
                    assertEquals(Series.WL3, record.series(), part);
                    singleApplicationCores++;
                }
                default -> throw new AssertionError("Unexpected part " + part);
            }
            if (record.status() == Status.NETWORK_CORE_PINNED) {
                assertEquals(Stm32WirelessRecord.Management.NETWORK_CORE_MANAGED,
                    record.radioSubsystem().management(), part);
            }
            else {
                assertEquals(Stm32WirelessRecord.Management.APPLICATION_CORE_MANAGED,
                    record.radioSubsystem().management(), part);
                assertNull(record.networkCore(), part);
                assertNull(record.sharedResources().workspace(), part);
            }
            assertEquals(Stm32WirelessRecord.RegisterModel.UNAVAILABLE,
                record.radioSubsystem().registerModel(), part);
            String expectedRadioReason = switch (loads.applicability().requireEntry(part)
                .status()) {
                case EXACT_SVD_SHIPPED -> "RADIO_REGISTERS_NOT_IN_PINNED_REGISTER_MODELS";
                case EXACT_SVD_DEFERRED -> "RADIO_REGISTERS_DEFERRED_WITH_THE_DEVICE_LINE";
                default -> "RADIO_REGISTERS_UNAVAILABLE_WITH_THE_DEVICE_LINE";
            };
            assertEquals(expectedRadioReason,
                record.radioSubsystem().registerModelReason(), part);
        }
        assertEquals(2, pinnedNetworkCores);
        assertEquals(8, singleApplicationCores);
        assertEquals(10, WIRELESS_SCOPE.size());
    }

    @Test
    void perCoreRegisterModelsFollowThePinnedApplicabilityReview() throws Exception {
        SeededLoads loads = loaders();

        record Expectation(Stm32WirelessRecord.RegisterModel model, String file, String reason) {
        }

        Map<String, Expectation> expected = Map.of(
            "STM32WB55RGV6", new Expectation(Stm32WirelessRecord.RegisterModel.SHIPPED,
                "STM32WB55_CM4", null),
            "STM32WB15CCU6", new Expectation(Stm32WirelessRecord.RegisterModel.DEFERRED,
                "STM32WB15_CM4", "DUAL_CORE_M4_SVD_AVAILABLE_M0P_DEVICE_LINE_ABSENT"),
            "STM32WB05KZV6TR", new Expectation(Stm32WirelessRecord.RegisterModel.DEFERRED,
                "STM32WB05", "REGISTER_MODEL_MATERIALIZATION_DEFERRED"),
            "STM32WB07CCV6TR", new Expectation(Stm32WirelessRecord.RegisterModel.DEFERRED,
                "STM32WB07", "REGISTER_MODEL_MATERIALIZATION_DEFERRED"),
            "STM32WB09KEV6TR", new Expectation(Stm32WirelessRecord.RegisterModel.DEFERRED,
                "STM32WB09", "REGISTER_MODEL_MATERIALIZATION_DEFERRED"),
            "STM32WBA25CEU7", new Expectation(Stm32WirelessRecord.RegisterModel.UNAVAILABLE,
                null, "NO_EXACT_SVD_DEVICE_LINE_IN_PINNED_SOURCE"),
            "STM32WBA52CGU6", new Expectation(Stm32WirelessRecord.RegisterModel.DEFERRED,
                "STM32WBA52", "REGISTER_MODEL_MATERIALIZATION_DEFERRED"),
            "STM32WBA65RIV7", new Expectation(Stm32WirelessRecord.RegisterModel.UNAVAILABLE,
                null, "NO_EXACT_SVD_DEVICE_LINE_IN_PINNED_SOURCE"),
            "STM32WL33CCV6TR", new Expectation(Stm32WirelessRecord.RegisterModel.DEFERRED,
                "STM32WL33", "REGISTER_MODEL_MATERIALIZATION_DEFERRED"),
            "STM32WL3RKBV6", new Expectation(Stm32WirelessRecord.RegisterModel.UNAVAILABLE,
                null, "NO_EXACT_SVD_DEVICE_LINE_IN_PINNED_SOURCE"));
        for (Map.Entry<String, Expectation> entry : expected.entrySet()) {
            Stm32WirelessRecord record = compose(composeInputs(loads, entry.getKey()));
            assertEquals(entry.getValue().model(),
                record.applicationCore().registerModel(), entry.getKey());
            if (entry.getValue().file() == null) {
                assertNull(record.applicationCore().svdFile(), entry.getKey());
            }
            else {
                assertEquals(entry.getValue().file(),
                    record.applicationCore().svdFile().deviceName(), entry.getKey());
            }
            assertEquals(entry.getValue().reason(),
                record.applicationCore().registerModelReason(), entry.getKey());
        }
    }

    @Test
    void nonWirelessPartsFailClosedByFamilyScope() throws Exception {
        SeededLoads loads = loaders();
        int rejected = 0;
        for (String part : nonWirelessParts(loads.parts())) {
            WirelessPlanException exception = assertThrows(WirelessPlanException.class,
                () -> compose(composeInputs(loads, part)), part);
            assertEquals(Diagnostic.WIRELESS_FAMILY_OUT_OF_SCOPE, exception.diagnostic(),
                part);
            rejected++;
        }
        assertEquals(43, rejected);
    }

    @Test
    void partMismatchAndWorkspaceAgreementFailClosed() throws Exception {
        SeededLoads loads = loaders();
        Inputs f103 = composeInputs(loads, "STM32F103C8T6");
        Inputs wb55 = composeInputs(loads, "STM32WB55RGV6");
        WirelessPlanException mismatch = assertThrows(WirelessPlanException.class,
            () -> Stm32WirelessPlanner.compose(f103.catalogPart(), f103.plan(), null,
                wb55.securityRecord(), f103.entry()));
        assertEquals(Diagnostic.WIRELESS_PART_MISMATCH, mismatch.diagnostic());
        WirelessPlanException unpinned = assertThrows(WirelessPlanException.class,
            () -> Stm32WirelessPlanner.compose(wb55.catalogPart(), wb55.plan(), null,
                wb55.securityRecord(), wb55.entry()));
        assertEquals(Diagnostic.WIRELESS_WORKSPACE_UNPINNED, unpinned.diagnostic());
    }

    @Test
    void wb55BindingClassificationFollowsThePinnedCpu2Attribution() throws Exception {
        SeededLoads loads = loaders();
        Inputs wb55 = composeInputs(loads, "STM32WB55RGV6");
        NetworkCoreImageBinding sram1 = Stm32WirelessPlanner.evaluateNetworkCoreImage(
            wb55.plan(), wb55.workspace(), new AddressRange("ram", 0x20000000L, 0x4000L));
        assertEquals(NetworkCoreImageBinding.State.BINDABLE_UNRESOLVED_FETCH_VIEW,
            sram1.state());
        assertEquals(List.of("SRAM1"), sram1.regionIds());
        assertEquals("cpu2-fetch-view", sram1.fetchView().id());
        NetworkCoreImageBinding spanning = Stm32WirelessPlanner.evaluateNetworkCoreImage(
            wb55.plan(), wb55.workspace(), new AddressRange("ram", 0x20000000L, 0x38000L));
        assertEquals(NetworkCoreImageBinding.State.BINDABLE_UNRESOLVED_FETCH_VIEW,
            spanning.state());
        assertEquals(List.of("SRAM1", "SRAM2A"), spanning.regionIds());
        NetworkCoreImageBinding border = Stm32WirelessPlanner.evaluateNetworkCoreImage(
            wb55.plan(), wb55.workspace(), new AddressRange("ram", 0x2002F000L, 0x2000L));
        assertEquals(NetworkCoreImageBinding.State.BINDABLE_UNRESOLVED_FETCH_VIEW,
            border.state());
        assertEquals(List.of("SRAM1", "SRAM2A"), border.regionIds());
        NetworkCoreImageBinding spanningSram2 = Stm32WirelessPlanner.evaluateNetworkCoreImage(
            wb55.plan(), wb55.workspace(), new AddressRange("ram", 0x20030000L, 0x8010L));
        assertEquals(NetworkCoreImageBinding.State.BINDABLE_UNRESOLVED_FETCH_VIEW,
            spanningSram2.state());
        assertEquals(List.of("SRAM2A", "SRAM2B"), spanningSram2.regionIds());
        NetworkCoreImageBinding flash = Stm32WirelessPlanner.evaluateNetworkCoreImage(
            wb55.plan(), wb55.workspace(), new AddressRange("ram", 0x08000000L, 0x1000L));
        assertEquals(NetworkCoreImageBinding.State.FLASH_VIEW_CONFIGURATION_DEPENDENT,
            flash.state());
        assertEquals(List.of("FLASH"), flash.regionIds());
        WirelessPlanException partial = assertThrows(WirelessPlanException.class,
            () -> Stm32WirelessPlanner.evaluateNetworkCoreImage(wb55.plan(), wb55.workspace(),
                new AddressRange("ram", 0x2003F000L, 0x2000L)));
        assertEquals(Diagnostic.BINDING_RANGE_NOT_CPU2_ACCESSIBLE, partial.diagnostic());
        WirelessPlanException foreign = assertThrows(WirelessPlanException.class,
            () -> Stm32WirelessPlanner.evaluateNetworkCoreImage(wb55.plan(), wb55.workspace(),
                new AddressRange("ram", 0x40000000L, 0x1000L)));
        assertEquals(Diagnostic.BINDING_RANGE_NOT_CPU2_ACCESSIBLE, foreign.diagnostic());
    }

    @Test
    void bindingInputsFailClosed() throws Exception {
        SeededLoads loads = loaders();
        Inputs wb55 = composeInputs(loads, "STM32WB55RGV6");
        Inputs f103 = composeInputs(loads, "STM32F103C8T6");
        WirelessPlanException empty = assertThrows(WirelessPlanException.class,
            () -> Stm32WirelessPlanner.evaluateNetworkCoreImage(wb55.plan(), wb55.workspace(),
                new AddressRange("ram", 0x20000000L, 0L)));
        assertEquals(Diagnostic.BINDING_IMAGE_EMPTY, empty.diagnostic());
        WirelessPlanException space = assertThrows(WirelessPlanException.class,
            () -> Stm32WirelessPlanner.evaluateNetworkCoreImage(wb55.plan(), wb55.workspace(),
                new AddressRange("peripheral", 0x58000C00L, 0x400L)));
        assertEquals(Diagnostic.BINDING_IMAGE_OUT_OF_SPACE, space.diagnostic());
        WirelessPlanException oversize = assertThrows(WirelessPlanException.class,
            () -> Stm32WirelessPlanner.evaluateNetworkCoreImage(wb55.plan(), wb55.workspace(),
                new AddressRange("ram", 0xFFFFFFF0L, 0x20L)));
        assertEquals(Diagnostic.BINDING_IMAGE_OUT_OF_SPACE, oversize.diagnostic());
        WirelessPlanException unpinned = assertThrows(WirelessPlanException.class,
            () -> Stm32WirelessPlanner.evaluateNetworkCoreImage(f103.plan(), f103.workspace(),
                new AddressRange("ram", 0x20000000L, 0x1000L)));
        assertEquals(Diagnostic.BINDING_WORKSPACE_UNPINNED, unpinned.diagnostic());
        WirelessPlanException crossed = assertThrows(WirelessPlanException.class,
            () -> Stm32WirelessPlanner.evaluateNetworkCoreImage(f103.plan(), wb55.workspace(),
                new AddressRange("ram", 0x20000000L, 0x1000L)));
        assertEquals(Diagnostic.BINDING_PART_MISMATCH, crossed.diagnostic());
    }

    @Test
    void wb55RadioRegisterAbsenceIsVerifiedAgainstTheShippedPacks() throws Exception {
        var limits = ParserLimits.defaults();
        var token = CancellationToken.none();
        for (String pack : new String[] {"stm32wb55-cm4", "stm32wb55-cm0p"}) {
            byte[] registers = Files.readAllBytes(
                Path.of("packs/stm32.%s.svd/1.0.0/registers.json".formatted(pack)));
            Map<?, ?> root = (Map<?, ?>) StrictJsonParser.parse(registers, limits, token);
            List<?> peripherals = (List<?>) root.get("peripherals");
            assertTrue(peripherals != null && !peripherals.isEmpty(), pack);
            boolean hasIpcc = false;
            boolean hasHsem = false;
            for (Object value : peripherals) {
                String name = String.valueOf(((Map<?, ?>) value).get("name"));
                assertFalse(name.startsWith("RF"), pack + " ships " + name);
                assertFalse(name.equals("RADIO") || name.startsWith("RADIO_"),
                    pack + " ships " + name);
                assertFalse(name.equals("BLE") || name.contains("_BLE"),
                    pack + " ships " + name);
                hasIpcc |= name.equals("IPCC");
                hasHsem |= name.equals("HSEM");
            }
            assertTrue(hasIpcc, pack);
            assertTrue(hasHsem, pack);
        }
    }

    @Test
    void compositionIsDeterministicForTheSamePinnedInputs() throws Exception {
        Stm32WirelessRecord first = compose(composeInputs(loaders(), "STM32WB55RGV6"));
        assertEquals(first, compose(composeInputs(loaders(), "STM32WB55RGV6")));
    }

    private record SeededLoads(Stm32MemoryPlanner memory, Stm32DevicePackRegistry parts,
            Stm32SecurityCatalog security, Stm32SvdApplicability applicability) {
    }

    private record Inputs(Stm32DevicePackRegistry.Part catalogPart,
            Stm32MemoryPlanner.Plan plan, Stm32WorkspacePlan workspace,
            Stm32SecurityRecord securityRecord, Stm32SvdApplicability.Entry entry) {
    }

    private record Composed(Inputs inputs, Stm32WirelessRecord record) {
    }

    private static SeededLoads loaders() throws IOException, DiagnosticException {
        var limits = ParserLimits.defaults();
        var token = CancellationToken.none();
        var ids = Stm32CuratedPartIds.load(SELECTION, limits, token);
        return new SeededLoads(
            Stm32MemoryPlanner.load(MEMORY_PLANS, ids, limits, token),
            Stm32DevicePackRegistry.load(CATALOG, ids, limits, token),
            Stm32SecurityCatalog.load(SECURITY_DOMAINS, ids, limits, token),
            Stm32SvdApplicability.load(SVD_APPLICABILITY, ids, limits, token));
    }

    private static Inputs composeInputs(SeededLoads loads, String part)
            throws IOException, DiagnosticException {
        Stm32DevicePackRegistry.Part catalogPart = loads.parts().selectExact(part);
        Stm32MemoryPlanner.Plan plan =
            loads.memory().plan(part, Stm32MemoryPlanner.BootMode.UNKNOWN);
        Stm32SecurityRecord securityRecord = loads.security().requireRecord(part);
        Stm32WorkspacePlan workspace = Stm32WorkspacePlanner.compose(plan, securityRecord);
        Stm32SvdApplicability.Entry entry = loads.applicability().requireEntry(part);
        return new Inputs(catalogPart, plan, workspace, securityRecord, entry);
    }

    private static Stm32WirelessRecord compose(Inputs inputs) {
        return Stm32WirelessPlanner.compose(inputs.catalogPart(), inputs.plan(),
            inputs.workspace(), inputs.securityRecord(), inputs.entry());
    }

    private static Composed compose(String part) throws Exception {
        Inputs inputs = composeInputs(loaders(), part);
        return new Composed(inputs, compose(inputs));
    }

    private static List<String> nonWirelessParts(Stm32DevicePackRegistry parts) {
        return parts.parts().stream()
            .map(Stm32DevicePackRegistry.Part::exactPart)
            .filter(part -> !WIRELESS_SCOPE.contains(part))
            .toList();
    }
}
