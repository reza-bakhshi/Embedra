package io.github.rezabakhshi.embedra.targets.stm32.workspace;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.io.AddressRange;
import io.github.rezabakhshi.embedra.core.model.BootRelationship;
import io.github.rezabakhshi.embedra.core.model.BootRelationshipType;
import io.github.rezabakhshi.embedra.core.model.CommunicationKind;
import io.github.rezabakhshi.embedra.core.model.Confidence;
import io.github.rezabakhshi.embedra.core.model.Evidence;
import io.github.rezabakhshi.embedra.core.model.EvidenceKind;
import io.github.rezabakhshi.embedra.core.model.ExecutionTopology;
import io.github.rezabakhshi.embedra.core.model.FirmwareSource;
import io.github.rezabakhshi.embedra.core.model.InterProcessorLink;
import io.github.rezabakhshi.embedra.core.model.ProcessorKind;
import io.github.rezabakhshi.embedra.core.model.ProcessorNode;
import io.github.rezabakhshi.embedra.core.model.ProgramStrategy;
import io.github.rezabakhshi.embedra.core.model.SecurityDomain;
import io.github.rezabakhshi.embedra.core.model.SecurityDomainKind;
import io.github.rezabakhshi.embedra.core.model.SharedMemoryRegion;
import io.github.rezabakhshi.embedra.targets.stm32.catalog.Stm32CuratedPartIds;
import io.github.rezabakhshi.embedra.targets.stm32.memory.Stm32MemoryPlanner;
import io.github.rezabakhshi.embedra.targets.stm32.memory.Stm32MemoryPlanner.Region;
import io.github.rezabakhshi.embedra.targets.stm32.security.Stm32SecurityAttribute;
import io.github.rezabakhshi.embedra.targets.stm32.security.Stm32SecurityCatalog;
import io.github.rezabakhshi.embedra.targets.stm32.security.Stm32SecurityHeaderSource;
import io.github.rezabakhshi.embedra.targets.stm32.security.Stm32SecurityPlanner;
import io.github.rezabakhshi.embedra.targets.stm32.security.Stm32SecurityRecord;
import io.github.rezabakhshi.embedra.targets.stm32.security.Stm32SecurityRecord.EvidenceState;
import io.github.rezabakhshi.embedra.targets.stm32.security.Stm32SecurityWindow;
import io.github.rezabakhshi.embedra.targets.stm32.workspace.Stm32WorkspacePlan.ImageDomain.State;
import io.github.rezabakhshi.embedra.targets.stm32.workspace.Stm32WorkspacePlan.MemoryView.Ownership;
import io.github.rezabakhshi.embedra.targets.stm32.workspace.Stm32WorkspacePlanner.Diagnostic;
import io.github.rezabakhshi.embedra.targets.stm32.workspace.Stm32WorkspacePlanner.WorkspacePlanException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** Composition, fail-closed, and workspace-model regression tests on pinned catalogs. */
class Stm32WorkspacePlannerTest {
    private static final Path SELECTION = Path.of("catalogs/stm32/2026-09-29/selection.json");

    private static final Path MEMORY_PLANS = Path.of("catalogs/stm32/2026-09-29/memory-plans.json");

    private static final Path SECURITY_DOMAINS =
        Path.of("catalogs/stm32/2026-09-29/security-domains.json");

    private static final String RELEASE_MECHANISM =
        "Synthetic RM: after reset CPU2 boots only once CPU1 sets C2BOOT";

    private static final String SYNTH = "SYNTHETIC_DEVICE";

    @Test
    void wb55WorkspacePlansTwoOwnershipDomainsWithoutMutatingThePlan() throws Exception {
        var plan = memory().plan("STM32WB55RGV6", Stm32MemoryPlanner.BootMode.UNKNOWN);
        var regionsBefore = List.copyOf(plan.regions());
        var aliasesBefore = List.copyOf(plan.aliases());
        var topologyBefore = plan.topology();
        Stm32SecurityRecord record = security().requireRecord("STM32WB55RGV6");
        Stm32WorkspacePlan workspace = Stm32WorkspacePlanner.compose(plan, record, Map.of());
        assertTrue(workspace.pinned());
        assertEquals(Stm32WorkspacePlan.Status.MULTI_CORE_PINNED, workspace.status());
        assertEquals("PLANNED", workspace.supportState());
        assertNull(workspace.reason());
        assertNull(workspace.securityMap());
        assertSame(plan, workspace.mcuPlan());
        assertSame(record, workspace.securityRecord());
        assertSame(topologyBefore, plan.topology());
        assertEquals(regionsBefore, plan.regions());
        assertEquals(aliasesBefore, plan.aliases());

        assertEquals(2, workspace.programs().size());
        Stm32WorkspacePlan.ProgramSlot shared = workspace.programs().getFirst();
        Stm32WorkspacePlan.ProgramSlot independent = workspace.programs().get(1);
        assertEquals("cpu1-program", shared.id());
        assertEquals("cpu1", shared.nodeId());
        assertEquals("Application Cortex-M4", shared.role());
        assertEquals(FirmwareSource.SHARED_IMAGE, shared.firmwareSource());
        assertEquals("ARMv7E-M Thumb little-endian", shared.instructionSet());
        assertEquals("ARM:LE:32:Cortex", shared.ghidraLanguageId());
        assertEquals(State.PINNED_DEVICE_IMAGE, shared.imageDomain().state());
        assertEquals(plan.regions().stream().filter(region -> region.id().equals("FLASH"))
            .findFirst().orElseThrow().range(), shared.imageDomain().range());
        assertTrue(shared.memoryViews().stream().anyMatch(view -> "FLASH".equals(view.kind())
            && view.ownership() == Ownership.PRIVATE && view.peerSlotIds().isEmpty()));
        assertTrue(shared.memoryViews().stream().anyMatch(view -> "SRAM1".equals(view.regionId())
            && view.ownership() == Ownership.SHARED
            && view.peerSlotIds().equals(Set.of("cpu2-program"))));
        assertTrue(shared.memoryViews().stream().noneMatch(
            view -> "SRAM2A".equals(view.regionId())));

        assertEquals("cpu2-program", independent.id());
        assertEquals("cpu2", independent.nodeId());
        assertEquals("Network Cortex-M0+", independent.role());
        assertEquals(FirmwareSource.INDEPENDENT_IMAGE, independent.firmwareSource());
        assertEquals("ARMv6-M Thumb little-endian", independent.instructionSet());
        assertEquals(State.UNAVAILABLE_INDEPENDENTLY_SUPPLIED, independent.imageDomain().state());
        assertNull(independent.imageDomain().range());
        assertTrue(independent.imageDomain().reason().contains("independently"));
        assertTrue(independent.memoryViews().stream().allMatch(view -> "RAM".equals(view.kind())));
        assertTrue(independent.memoryViews().stream().anyMatch(view -> "SRAM1".equals(view.regionId())
            && view.ownership() == Ownership.SHARED));
        assertTrue(independent.memoryViews().stream().anyMatch(
            view -> "SRAM2A".equals(view.regionId()) && view.ownership() == Ownership.PRIVATE));
        assertTrue(independent.memoryViews().stream().anyMatch(
            view -> "SRAM2B".equals(view.regionId()) && view.ownership() == Ownership.PRIVATE));
        assertEquals(1, independent.unresolvedViews().size());
        assertEquals("cpu2-fetch-view", independent.unresolvedViews().getFirst().id());
        assertTrue(independent.unresolvedViews().getFirst().reason().contains("configuration"));

        Map<String, Stm32WorkspacePlan.CrossProgramReference> references = new LinkedHashMap<>();
        for (Stm32WorkspacePlan.CrossProgramReference reference : workspace.crossProgramReferences()) {
            references.put(reference.id(), reference);
        }
        assertEquals(4, references.size());
        Stm32WorkspacePlan.CrossProgramReference mailbox =
            references.get("ipcc-mailbox:cpu2-program");
        assertEquals(Stm32WorkspacePlan.CrossProgramReference.Kind.SHARED_MAILBOX, mailbox.kind());
        assertEquals(new AddressRange("peripheral", 0x58000C00L, 0x400L), mailbox.sharedRanges()
            .getFirst());
        assertFalse(mailbox.evidence().isEmpty());
        Stm32WorkspacePlan.CrossProgramReference semaphore =
            references.get("hsem-semaphore:cpu2-program");
        assertEquals(Stm32WorkspacePlan.CrossProgramReference.Kind.SHARED_SEMAPHORE,
            semaphore.kind());
        assertEquals(new AddressRange("peripheral", 0x58001400L, 0x400L),
            semaphore.sharedRanges().getFirst());
        Stm32WorkspacePlan.CrossProgramReference boot = references.get("boot-cpu1-releases-cpu2");
        assertEquals(Stm32WorkspacePlan.CrossProgramReference.Kind.BOOT_HANDOFF, boot.kind());
        assertEquals("cpu1-program", boot.fromSlotId());
        assertEquals("cpu2-program", boot.toSlotId());
        assertTrue(boot.sharedRanges().isEmpty());
        assertTrue(boot.mechanism().contains("C2BOOT"));
        Stm32WorkspacePlan.CrossProgramReference sram1 = references.get("SRAM1-shared:cpu2-program");
        assertEquals(Stm32WorkspacePlan.CrossProgramReference.Kind.SHARED_MEMORY, sram1.kind());
        assertEquals(1, sram1.sharedRanges().size());
        assertEquals(0x20000000L, sram1.sharedRanges().getFirst().start());
        assertEquals(196608, sram1.sharedRanges().getFirst().length());
        assertTrue(sram1.mechanism().contains("readers"));
        assertTrue(sram1.mechanism().contains("writers"));
        assertFalse(workspace.evidence().isEmpty());
        assertTrue(workspace.evidence().stream().anyMatch(entry -> entry.source().contains(
            "00def2817ba0660644a4bc6cea3ffb756e11aff4d7236a466f82de838c280c66")));
        assertTrue(workspace.evidence().stream().anyMatch(entry -> entry.source().contains(
            "08da45f506d670df3ed042243513d0a3751d07cce2b256cb2c46cd7db23ee3e9")));
        assertEquals(2, plan.topology().processors().stream()
            .filter(node -> node.kind() == ProcessorKind.CPU_CORE).count());
    }

    @Test
    void compositionIsDeterministicForTheSamePinnedInputs() throws Exception {
        var planner = memory();
        Stm32SecurityCatalog catalog = security();
        Stm32MemoryPlanner.Plan plan =
            planner.plan("STM32WB55RGV6", Stm32MemoryPlanner.BootMode.UNKNOWN);
        Stm32SecurityRecord record = catalog.requireRecord("STM32WB55RGV6");
        Stm32WorkspacePlan first = Stm32WorkspacePlanner.compose(plan, record);
        assertEquals(first, Stm32WorkspacePlanner.compose(plan, record));
        Stm32MemoryPlanner.Plan reloaded =
            planner.plan("STM32WB55RGV6", Stm32MemoryPlanner.BootMode.UNKNOWN);
        assertEquals(first, Stm32WorkspacePlanner.compose(reloaded,
            catalog.requireRecord("STM32WB55RGV6")));
    }

    @Test
    void wb15PlansItsOwnLayoutWithCpu2OnlySram2Backing() throws Exception {
        Stm32WorkspacePlan workspace = Stm32WorkspacePlanner.compose(
            memory().plan("STM32WB15CCU6", Stm32MemoryPlanner.BootMode.UNKNOWN),
            security().requireRecord("STM32WB15CCU6"));
        assertTrue(workspace.pinned());
        assertEquals(2, workspace.programs().size());
        Stm32WorkspacePlan.ProgramSlot shared = workspace.programs().getFirst();
        assertTrue(shared.memoryViews().stream().anyMatch(view -> "SRAM1".equals(view.regionId())
            && view.ownership() == Ownership.SHARED && view.range().length() == 12288));
        Stm32WorkspacePlan.ProgramSlot independent = workspace.programs().get(1);
        assertTrue(independent.memoryViews().stream().anyMatch(
            view -> "SRAM2B".equals(view.regionId()) && view.ownership() == Ownership.PRIVATE
                && view.range().length() == 4096));
        assertEquals(4, workspace.crossProgramReferences().size());
    }

    @Test
    void everyCuratedPartIsEitherPinnedDualCoreOrExplicitlyUnavailable() throws Exception {
        var planner = memory();
        Stm32SecurityCatalog catalog = security();
        List<String> pinnedParts = new ArrayList<>();
        for (Stm32SecurityRecord record : catalog.records()) {
            String part = record.exactPart();
            Stm32WorkspacePlan workspace = Stm32WorkspacePlanner.compose(
                planner.plan(part, Stm32MemoryPlanner.BootMode.UNKNOWN), record);
            assertEquals("PLANNED", workspace.supportState(), part);
            if (part.equals("STM32WB55RGV6") || part.equals("STM32WB15CCU6")) {
                assertTrue(workspace.pinned(), part);
                assertFalse(workspace.programs().isEmpty(), part);
                assertFalse(workspace.crossProgramReferences().isEmpty(), part);
                assertNull(workspace.reason(), part);
                pinnedParts.add(part);
            }
            else {
                assertEquals(Stm32WorkspacePlan.Status.UNAVAILABLE, workspace.status(), part);
                assertTrue(workspace.reason().startsWith("SINGLE_CORE_EXECUTION_TOPOLOGY"), part);
                assertTrue(workspace.reason()
                    .contains("no second core or coprocessor image exists in the pinned sources"),
                    part);
                assertTrue(workspace.programs().isEmpty(), part);
                assertTrue(workspace.crossProgramReferences().isEmpty(), part);
                assertNull(workspace.securityMap(), part);
                if (part.startsWith("STM32H7")) {
                    assertTrue(workspace.reason().contains("executable CPU core(s)"), part);
                }
            }
        }
        assertEquals(2, pinnedParts.size());
        assertEquals(53, catalog.records().size());
    }

    @Test
    void partMismatchFailsClosedBeforeAnyWorkspaceDataIsProduced() throws Exception {
        Stm32SecurityRecord record = security().requireRecord("STM32WB55RGV6");
        Stm32MemoryPlanner.Plan f103 =
            memory().plan("STM32F103C8T6", Stm32MemoryPlanner.BootMode.UNKNOWN);
        expectFailure(Diagnostic.WORKSPACE_PART_MISMATCH, f103, record);
    }

    @Test
    void unknownConfigurationInputFailsClosed() throws Exception {
        Stm32MemoryPlanner.Plan plan =
            memory().plan("STM32WB55RGV6", Stm32MemoryPlanner.BootMode.UNKNOWN);
        Stm32SecurityRecord record = security().requireRecord("STM32WB55RGV6");
        WorkspacePlanException exception = assertThrows(WorkspacePlanException.class,
            () -> Stm32WorkspacePlanner.compose(plan, record, Map.of("C2OPT", "0")));
        assertEquals(Diagnostic.WORKSPACE_CONFIGURATION_UNKNOWN, exception.diagnostic());
    }

    @Test
    void unavailableWorkspaceCarriesNoSecurityMapButKeepsTheRecord() throws Exception {
        Stm32SecurityRecord record = security().requireRecord("STM32H573IIK3Q");
        Stm32MemoryPlanner.Plan plan =
            memory().plan("STM32H573IIK3Q", Stm32MemoryPlanner.BootMode.UNKNOWN);
        assertTrue(record.pinned());
        Stm32WorkspacePlan workspace = Stm32WorkspacePlanner.compose(plan, record);
        assertFalse(workspace.pinned());
        assertNull(workspace.securityMap());
        assertSame(record, workspace.securityRecord());
        assertTrue(workspace.programs().isEmpty());
    }

    @Test
    void syntheticBasePlanComposesIntoAPinnedWorkspace() {
        Stm32WorkspacePlan workspace =
            Stm32WorkspacePlanner.compose(synthetic().build(), syntheticRecord());
        assertTrue(workspace.pinned());
        assertEquals(2, workspace.programs().size());
        assertEquals(Stm32WorkspacePlan.Status.MULTI_CORE_PINNED, workspace.status());
        Stm32WorkspacePlan.ProgramSlot independent = workspace.programs().get(1);
        assertEquals(State.UNAVAILABLE_INDEPENDENTLY_SUPPLIED, independent.imageDomain().state());
        assertTrue(independent.unresolvedViews().getFirst().reason().contains("C2BOOT"));
        assertEquals("SRAMA", independent.memoryViews().stream()
            .filter(view -> view.ownership() == Ownership.SHARED)
            .findFirst().orElseThrow().regionId());
        assertTrue(independent.memoryViews().stream()
            .filter(view -> view.regionId().equals("SRAMB"))
            .allMatch(view -> view.ownership() == Ownership.PRIVATE));
        assertEquals(4, workspace.crossProgramReferences().size());
    }

    @Test
    void bootOrderMailboxAndSemaphoreFactsMustBePinned() {
        expectFailure(Diagnostic.WORKSPACE_BOOT_ORDER_UNPINNED,
            synthetic().withoutBootRelationship().build(), syntheticRecord());
        expectFailure(Diagnostic.WORKSPACE_BOOT_ORDER_AMBIGUOUS,
            synthetic().withDuplicateBootRelationship().build(), syntheticRecord());
        expectFailure(Diagnostic.WORKSPACE_BOOT_ORDER_UNPINNED,
            synthetic().withBootReleasedFromBootRom().build(), syntheticRecord());
        expectFailure(Diagnostic.WORKSPACE_MAILBOX_UNPINNED,
            synthetic().withoutMailbox().build(), syntheticRecord());
        expectFailure(Diagnostic.WORKSPACE_SEMAPHORE_UNPINNED,
            synthetic().withoutSemaphore().build(), syntheticRecord());
        expectFailure(Diagnostic.WORKSPACE_COMMUNICATION_RANGE_UNPINNED,
            synthetic().withoutRegisterRanges().build(), syntheticRecord());
    }

    @Test
    void ambiguousDuplicateAndUndeterminedCoresFailClosed() {
        expectFailure(Diagnostic.WORKSPACE_CORES_AMBIGUOUS,
            synthetic().withClonedCpu2Identity().build(), syntheticRecord());
        expectFailure(Diagnostic.WORKSPACE_IMAGE_DOMAIN_AMBIGUOUS,
            synthetic().withCpu2Source(FirmwareSource.SHARED_IMAGE).build(), syntheticRecord());
        expectFailure(Diagnostic.WORKSPACE_IMAGE_DOMAIN_UNDETERMINED,
            synthetic().withCpu1Source(FirmwareSource.UNKNOWN).build(), syntheticRecord());
        expectFailure(Diagnostic.WORKSPACE_IMAGE_DOMAIN_UNDETERMINED,
            synthetic().withCpu2Source(FirmwareSource.ROM).build(), syntheticRecord());
        expectFailure(Diagnostic.WORKSPACE_IMAGE_UNDETERMINED,
            synthetic().withSecondFlashRegion().build(), syntheticRecord());
    }

    @Test
    void memoryAttributionAndBackingFactMustBePinned() {
        Stm32SecurityRecord record = syntheticRecord();
        assertThrows(IllegalArgumentException.class,
            () -> Stm32WorkspacePlanner.compose(synthetic().withUnknownSharedParticipant().build(),
                record));
        expectFailure(Diagnostic.WORKSPACE_MEMORY_UNATTRIBUTED,
            synthetic().withFlashSharedAccess().build(), record);
        expectFailure(Diagnostic.WORKSPACE_MEMORY_UNATTRIBUTED,
            synthetic().withUnattributedCpu1().build(), record);
        expectFailure(Diagnostic.WORKSPACE_MEMORY_UNATTRIBUTED,
            synthetic().withStrippedSharedBacking().build(), record);
        expectFailure(Diagnostic.WORKSPACE_SLOT_RANGE_OVERLAP,
            synthetic().withOverlappingUnsharedBanks().build(), record);
    }

    @Test
    void unresolvedPlanConfigurationFailsClosed() {
        expectFailure(Diagnostic.WORKSPACE_PLAN_CONFIGURATION_UNRESOLVED,
            synthetic().withUnresolvedConfiguration().build(), syntheticRecord());
    }

    @Test
    void pinnedSecurityRecordIsComposedIntoTheWorkspace() {
        Stm32WorkspacePlan workspace = Stm32WorkspacePlanner.compose(
            synthetic().withPinnedSecurity().build(), pinnedSyntheticRecord());
        assertTrue(workspace.pinned());
        assertNotNull(workspace.securityMap());
        assertEquals(1, workspace.securityMap().regions().size());
        assertEquals(Stm32SecurityAttribute.SECURE, workspace.securityMap().regions().getFirst()
            .attribute());
        assertEquals(0x10000000L, workspace.securityMap().regions().getFirst().range().start());
        assertFalse(workspace.securityMap().partitionResolved());
    }

    @Test
    void workspaceModelRejectsIncompleteOrInconsistentRecords() {
        Stm32MemoryPlanner.Plan plan = synthetic().build();
        Stm32SecurityRecord record = syntheticRecord();
        Stm32WorkspacePlan composed = Stm32WorkspacePlanner.compose(plan, record);
        assertThrows(IllegalArgumentException.class,
            () -> new Stm32WorkspacePlan(SYNTH, Stm32WorkspacePlan.Status.MULTI_CORE_PINNED,
                "unexpected reason", plan, record, null, composed.programs(),
                composed.crossProgramReferences(), composed.evidence()));
        assertThrows(IllegalArgumentException.class,
            () -> new Stm32WorkspacePlan(SYNTH, Stm32WorkspacePlan.Status.MULTI_CORE_PINNED, null,
                plan, record, null, List.of(), List.of(), composed.evidence()));
        assertThrows(IllegalArgumentException.class,
            () -> new Stm32WorkspacePlan(SYNTH, Stm32WorkspacePlan.Status.UNAVAILABLE, null, plan,
                record, null, List.of(), List.of(), composed.evidence()));
        assertThrows(IllegalArgumentException.class,
            () -> new Stm32WorkspacePlan(SYNTH, Stm32WorkspacePlan.Status.UNAVAILABLE, "reason",
                plan, record, null, composed.programs(), composed.crossProgramReferences(),
                composed.evidence()));
        Stm32SecurityPlanner.SecurityMap pinnedMap = Stm32SecurityPlanner.compose(
            synthetic().withPinnedSecurity().build(), pinnedSyntheticRecord());
        assertThrows(IllegalArgumentException.class,
            () -> new Stm32WorkspacePlan(SYNTH, Stm32WorkspacePlan.Status.UNAVAILABLE, "reason",
                plan, record, pinnedMap, List.of(), List.of(), composed.evidence()));
        List<Stm32WorkspacePlan.ProgramSlot> duplicated = List.of(composed.programs().getFirst(),
            composed.programs().getFirst());
        assertThrows(IllegalArgumentException.class,
            () -> new Stm32WorkspacePlan(SYNTH, Stm32WorkspacePlan.Status.MULTI_CORE_PINNED, null,
                plan, record, null, duplicated, composed.crossProgramReferences(),
                composed.evidence()));
        List<Stm32WorkspacePlan.CrossProgramReference> unknownEndpoint = List.of(
            new Stm32WorkspacePlan.CrossProgramReference("boot-x",
                Stm32WorkspacePlan.CrossProgramReference.Kind.BOOT_HANDOFF, "missing-slot",
                composed.programs().get(1).id(), List.of(), RELEASE_MECHANISM, Confidence.VERIFIED,
                composed.evidence()));
        assertThrows(IllegalArgumentException.class,
            () -> new Stm32WorkspacePlan(SYNTH, Stm32WorkspacePlan.Status.MULTI_CORE_PINNED, null,
                plan, record, null, composed.programs(), unknownEndpoint, composed.evidence()));
        List<Stm32WorkspacePlan.CrossProgramReference> selfLoop = List.of(
            new Stm32WorkspacePlan.CrossProgramReference("boot-x",
                Stm32WorkspacePlan.CrossProgramReference.Kind.BOOT_HANDOFF,
                composed.programs().getFirst().id(), composed.programs().getFirst().id(), List.of(),
                RELEASE_MECHANISM, Confidence.VERIFIED, composed.evidence()));
        assertThrows(IllegalArgumentException.class,
            () -> new Stm32WorkspacePlan(SYNTH, Stm32WorkspacePlan.Status.MULTI_CORE_PINNED, null,
                plan, record, null, composed.programs(), selfLoop, composed.evidence()));
        List<Stm32WorkspacePlan.CrossProgramReference> duplicatedReferences = List.of(
            composed.crossProgramReferences().getFirst(),
            composed.crossProgramReferences().getFirst());
        assertThrows(IllegalArgumentException.class,
            () -> new Stm32WorkspacePlan(SYNTH, Stm32WorkspacePlan.Status.MULTI_CORE_PINNED, null,
                plan, record, null, composed.programs(), duplicatedReferences,
                composed.evidence()));
        List<Stm32WorkspacePlan.MemoryView> unknownPeer = List.of(view("SRAMA", 0x20000000L,
            0x4000L, Ownership.SHARED, Set.of("missing-slot")));
        List<Stm32WorkspacePlan.ProgramSlot> withUnknownPeer = List.of(
            buildSlot("cpu1-program", unknownPeer));
        assertThrows(IllegalArgumentException.class,
            () -> new Stm32WorkspacePlan(SYNTH, Stm32WorkspacePlan.Status.MULTI_CORE_PINNED, null,
                plan, record, null, withUnknownPeer, composed.crossProgramReferences(),
                composed.evidence()));
    }

    @Test
    void workspaceModelRejectsOutOfRangeAndDuplicateViews() {
        assertThrows(IllegalArgumentException.class,
            () -> view("SRAMA", 0xFFFFFFF0L, 0x20L, Ownership.PRIVATE, Set.of()));
        assertThrows(IllegalArgumentException.class,
            () -> view("SRAMA", 0x20000000L, 0x0L, Ownership.PRIVATE, Set.of()));
        assertThrows(IllegalArgumentException.class, () -> buildSlot("cpu1-program", List.of(
            view("SRAMA", 0x20000000L, 0x4000L, Ownership.PRIVATE, Set.of()),
            view("SRAMB", 0x20001000L, 0x4000L, Ownership.PRIVATE, Set.of()))));
        assertThrows(IllegalArgumentException.class, () -> buildSlot("cpu1-program", List.of(
            view("SRAMA", 0x20000000L, 0x4000L, Ownership.PRIVATE, Set.of()),
            view("SRAMA", 0x20030000L, 0x2000L, Ownership.PRIVATE, Set.of()))));
        assertThrows(IllegalArgumentException.class,
            () -> view("SRAMA", 0x20000000L, 0x4000L, Ownership.SHARED, Set.of()));
        assertThrows(IllegalArgumentException.class,
            () -> view("SRAMA", 0x20000000L, 0x4000L, Ownership.PRIVATE, Set.of("other-slot")));
        assertThrows(IllegalArgumentException.class,
            () -> new Stm32WorkspacePlan.ImageDomain(State.PINNED_DEVICE_IMAGE, null, null));
        assertThrows(IllegalArgumentException.class, () -> new Stm32WorkspacePlan.ImageDomain(
            State.UNAVAILABLE_INDEPENDENTLY_SUPPLIED, new AddressRange("ram", 0, 16), null));
        assertThrows(IllegalArgumentException.class,
            () -> new Stm32WorkspacePlan.CrossProgramReference("boot-x",
                Stm32WorkspacePlan.CrossProgramReference.Kind.BOOT_HANDOFF, "cpu1-program",
                "cpu2-program", List.of(new AddressRange("ram", 0x20000000L, 16)),
                RELEASE_MECHANISM, Confidence.VERIFIED, evidence()));
        assertThrows(IllegalArgumentException.class,
            () -> new Stm32WorkspacePlan.CrossProgramReference("shared-x",
                Stm32WorkspacePlan.CrossProgramReference.Kind.SHARED_MAILBOX, "cpu1-program",
                "cpu2-program", List.of(), "mechanism", Confidence.VERIFIED, evidence()));
        assertThrows(IllegalArgumentException.class,
            () -> new Stm32WorkspacePlan.CrossProgramReference("shared-x",
                Stm32WorkspacePlan.CrossProgramReference.Kind.SHARED_MAILBOX, "cpu1-program",
                "cpu2-program", List.of(new AddressRange("ram", 0x20000000L, 0)), "mechanism",
                Confidence.VERIFIED, evidence()));
        assertThrows(IllegalArgumentException.class,
            () -> new Stm32WorkspacePlan.CrossProgramReference("shared-x",
                Stm32WorkspacePlan.CrossProgramReference.Kind.SHARED_MAILBOX, "cpu1-program",
                "cpu2-program", List.of(new AddressRange("ram", 0x20000000L, 16)), "mechanism",
                Confidence.VERIFIED, List.of()));
    }

    private static void expectFailure(Diagnostic expected, Stm32MemoryPlanner.Plan plan,
            Stm32SecurityRecord record) {
        WorkspacePlanException exception = assertThrows(WorkspacePlanException.class,
            () -> Stm32WorkspacePlanner.compose(plan, record));
        assertEquals(expected, exception.diagnostic());
    }

    private static List<Evidence> evidence() {
        return List.of(new Evidence(EvidenceKind.DOCUMENTED_FIELD, "synthetic-rm-rev-0",
            "Synthetic pinned workspace input"));
    }

    private static Stm32WorkspacePlan.MemoryView view(String regionId, long start, long length,
            Ownership ownership, Set<String> peers) {
        return new Stm32WorkspacePlan.MemoryView(regionId, "RAM", new AddressRange("ram", start,
            length), "rwx", ownership, peers);
    }

    private static Stm32WorkspacePlan.ProgramSlot buildSlot(String slotId,
            List<Stm32WorkspacePlan.MemoryView> views) {
        return new Stm32WorkspacePlan.ProgramSlot(slotId, slotId.replace("-program", ""),
            "Synthetic role", FirmwareSource.SHARED_IMAGE, "ARMv7E-M Thumb little-endian",
            "ARM:LE:32:Cortex", "default", SecurityDomain.unknown(),
            new Stm32WorkspacePlan.ImageDomain(State.PINNED_DEVICE_IMAGE,
                new AddressRange("ram", 0x08000000L, 0x40000L), null), views, List.of());
    }

    private static Stm32SecurityRecord syntheticRecord() {
        return new Stm32SecurityRecord(SYNTH, Stm32SecurityRecord.Status.UNAVAILABLE,
            "No pinned security windows for the synthetic device", List.of(syntheticHeader()),
            List.of(), List.of(), syntheticNsc(), syntheticVeneer());
    }

    private static Stm32SecurityRecord pinnedSyntheticRecord() {
        Stm32SecurityWindow window = new Stm32SecurityWindow("SYNTH_SRAMA_SEC",
            Stm32SecurityWindow.Kind.RAM, Stm32SecurityAttribute.SECURE,
            Stm32SecurityWindow.BoundaryKind.ALIAS_APERTURE, 0x10000000L, 0x4000L, "SRAMA",
            List.of("SYNTH_SRAMA_SEC_MIRROR"), "SYNTH_SRAMA_BASE_S", 42,
            "#define SYNTH_SRAMA_BASE_S 0x10000000UL", "cmsis/stm32synth.h",
            Stm32SecurityWindow.PartitionState.UNRESOLVED_CONFIGURATION_DEPENDENT);
        return new Stm32SecurityRecord(SYNTH, Stm32SecurityRecord.Status.ALIAS_VIEWS_PINNED, null,
            List.of(syntheticHeader()), List.of(window), List.of(), syntheticNsc(),
            syntheticVeneer());
    }

    private static Stm32SecurityHeaderSource syntheticHeader() {
        return new Stm32SecurityHeaderSource("https://github.com/synthetic/cmsis-test",
            "0123456789abcdef0123456789abcdef01234567", "cmsis/stm32synth.h",
            "a".repeat(64), "Apache-2.0");
    }

    private static Stm32SecurityRecord.NscBoundary syntheticNsc() {
        return new Stm32SecurityRecord.NscBoundary(EvidenceState.UNAVAILABLE,
            "The synthetic device pins no non-secure-callable boundary", List.of());
    }

    private static Stm32SecurityRecord.VeneerEvidence syntheticVeneer() {
        return new Stm32SecurityRecord.VeneerEvidence(EvidenceState.UNAVAILABLE,
            "The synthetic device pins no veneer transitions", null, List.of());
    }

    /** Hand-authored dual-core plan mirroring the pinned WB layout without catalog data. */
    private static final class SyntheticPlanBuilder {
        private final Map<String, Region> regions = new LinkedHashMap<>();

        private final List<ProcessorNode> processors = new ArrayList<>();

        private final Set<String> strippedBacking = new LinkedHashSet<>();

        private final List<Stm32MemoryPlanner.Alias> aliases = new ArrayList<>();

        private final List<Region> unresolved = new ArrayList<>();

        private final List<BootRelationship> boots = new ArrayList<>();

        private final List<InterProcessorLink> links = new ArrayList<>();

        private FirmwareSource cpu1Source = FirmwareSource.SHARED_IMAGE;

        private FirmwareSource cpu2Source = FirmwareSource.INDEPENDENT_IMAGE;

        private SyntheticPlanBuilder() {
            regions.put("FLASH", region("FLASH", "FLASH", 0x08000000L, 0x40000L, "rx", Map.of()));
            regions.put("SRAMA", region("SRAMA", "RAM", 0x20000000L, 0x4000L, "rwx",
                Map.of("cpu1", "rw", "cpu2", "rw")));
            regions.put("SRAMB", region("SRAMB", "RAM", 0x20030000L, 0x2000L, "rwx",
                Map.of("cpu2", "rw")));
            processors.add(core("cpu1", "Application Cortex-M4", cpu1Source,
                "ARMv7E-M Thumb little-endian"));
            processors.add(core("cpu2", "Network Cortex-M0+", cpu2Source,
                "ARMv6-M Thumb little-endian"));
            boots.add(bootRelease("cpu1-releases-cpu2", "cpu1"));
            links.add(link("ipcc-mailbox", CommunicationKind.MAILBOX, 0x58000C00L));
            links.add(link("hsem-semaphore", CommunicationKind.HARDWARE_SEMAPHORE, 0x58001400L));
        }

        SyntheticPlanBuilder withCpu1Source(FirmwareSource source) {
            cpu1Source = source;
            processors.set(0, core("cpu1", "Application Cortex-M4", source,
                "ARMv7E-M Thumb little-endian"));
            return this;
        }

        SyntheticPlanBuilder withCpu2Source(FirmwareSource source) {
            cpu2Source = source;
            processors.set(1, core("cpu2", "Network Cortex-M0+", source,
                "ARMv6-M Thumb little-endian"));
            return this;
        }

        SyntheticPlanBuilder withClonedCpu2Identity() {
            processors.set(1, core("cpu2", "Application Cortex-M4", cpu2Source,
                "ARMv7E-M Thumb little-endian"));
            return this;
        }

        SyntheticPlanBuilder withoutBootRelationship() {
            boots.clear();
            return this;
        }

        SyntheticPlanBuilder withDuplicateBootRelationship() {
            boots.add(bootRelease("cpu1-releases-cpu2-again", "cpu1"));
            return this;
        }

        SyntheticPlanBuilder withBootReleasedFromBootRom() {
            processors.add(new ProcessorNode("boot-rom", ProcessorKind.BOOT_ROM,
                Optional.of("ARMv7E-M Thumb little-endian"), Optional.of("ARM:LE:32:Cortex"),
                Optional.of("default"), "Factory boot context",
                new SecurityDomain("unpartitioned", SecurityDomainKind.CUSTOM), SYNTH,
                Set.of("ram"), List.of(), FirmwareSource.ROM, Confidence.VERIFIED,
                List.of()));
            boots.set(0, bootRelease("boot-rom-releases-cpu2", "boot-rom"));
            return this;
        }

        SyntheticPlanBuilder withoutMailbox() {
            links.removeIf(link -> link.kind() == CommunicationKind.MAILBOX);
            return this;
        }

        SyntheticPlanBuilder withoutSemaphore() {
            links.removeIf(link -> link.kind() == CommunicationKind.HARDWARE_SEMAPHORE);
            return this;
        }

        SyntheticPlanBuilder withoutRegisterRanges() {
            List<InterProcessorLink> replaced = new ArrayList<>();
            for (InterProcessorLink link : links) {
                replaced.add(new InterProcessorLink(link.id(), link.kind(),
                    link.participantNodeIds(), Optional.empty(), link.confidence(),
                    link.evidence()));
            }
            links.clear();
            links.addAll(replaced);
            return this;
        }

        SyntheticPlanBuilder withSecondFlashRegion() {
            regions.put("FLASH_ALIAS", region("FLASH_ALIAS", "FLASH", 0x08100000L, 0x40000L,
                "rx", Map.of()));
            return this;
        }

        SyntheticPlanBuilder withFlashSharedAccess() {
            regions.put("FLASH", region("FLASH", "FLASH", 0x08000000L, 0x40000L, "rx",
                Map.of("cpu1", "rw")));
            return this;
        }

        SyntheticPlanBuilder withUnknownSharedParticipant() {
            regions.put("SRAMA", region("SRAMA", "RAM", 0x20000000L, 0x4000L, "rwx",
                Map.of("cpu1", "rw", "cpu2", "rw", "cpu9", "rw")));
            return this;
        }

        SyntheticPlanBuilder withUnattributedCpu1() {
            regions.put("SRAMA", region("SRAMA", "RAM", 0x20000000L, 0x4000L, "rwx",
                Map.of("cpu2", "rw")));
            return this;
        }

        SyntheticPlanBuilder withStrippedSharedBacking() {
            strippedBacking.add("SRAMA");
            return this;
        }

        SyntheticPlanBuilder withOverlappingUnsharedBanks() {
            regions.put("SRAMA", region("SRAMA", "RAM", 0x20000000L, 0x4000L, "rwx",
                Map.of("cpu1", "rw")));
            regions.put("SRAMB", region("SRAMB", "RAM", 0x20001000L, 0x4000L, "rwx",
                Map.of("cpu2", "rw")));
            return this;
        }

        SyntheticPlanBuilder withUnresolvedConfiguration() {
            unresolved.add(region("ITCM_AXI_SHARED", "RAM", 0x24020000L, 0x30000L, "rwx", Map.of()));
            return this;
        }

        SyntheticPlanBuilder withPinnedSecurity() {
            aliases.add(new Stm32MemoryPlanner.Alias("SYNTH_SRAMA_SEC_MIRROR", "SRAMA",
                new AddressRange("ram", 0x10000000L, 0x4000L), "ALWAYS"));
            return this;
        }

        Stm32MemoryPlanner.Plan build() {
            List<SharedMemoryRegion> shared = new ArrayList<>();
            for (Region region : regions.values()) {
                if (strippedBacking.contains(region.id()) || region.sharedAccess().isEmpty()) {
                    continue;
                }
                Set<String> participants = Set.copyOf(region.sharedAccess().keySet());
                shared.add(new SharedMemoryRegion(region.id() + "-shared", region.range(),
                    participants, participants, participants, List.of(), Confidence.VERIFIED,
                    evidence()));
            }
            ExecutionTopology topology = new ExecutionTopology(List.copyOf(processors),
                List.copyOf(shared), List.copyOf(boots), List.copyOf(links), List.of(),
                ProgramStrategy.SHARED_PROGRAM);
            return new Stm32MemoryPlanner.Plan(SYNTH, List.copyOf(regions.values()),
                List.copyOf(aliases), List.of(), List.copyOf(unresolved), List.of(), topology,
                "AVAILABLE", null, null, List.of());
        }

        private static Region region(String id, String kind, long start, long length,
                String access, Map<String, String> sharedAccess) {
            return new Region(id, kind, new AddressRange("ram", start, length), access, "FIXED",
                sharedAccess);
        }

        private static ProcessorNode core(String id, String role, FirmwareSource source,
                String instructionSet) {
            return new ProcessorNode(id, ProcessorKind.CPU_CORE, Optional.of(instructionSet),
                Optional.of("ARM:LE:32:Cortex"), Optional.of("default"), role,
                new SecurityDomain("unpartitioned", SecurityDomainKind.CUSTOM), SYNTH,
                Set.of("ram"), List.of(), source, Confidence.VERIFIED, List.of());
        }

        private static BootRelationship bootRelease(String id, String source) {
            return new BootRelationship(id, source, "cpu2", BootRelationshipType.RELEASES_FROM_RESET,
                RELEASE_MECHANISM, Confidence.VERIFIED, evidence());
        }

        private static InterProcessorLink link(String id, CommunicationKind kind, long start) {
            return new InterProcessorLink(id, kind, Set.of("cpu1", "cpu2"),
                Optional.of(new AddressRange("peripheral", start, 0x400L)), Confidence.VERIFIED,
                evidence());
        }
    }

    private static SyntheticPlanBuilder synthetic() {
        return new SyntheticPlanBuilder();
    }

    private static Stm32MemoryPlanner memory() throws Exception {
        var limits = ParserLimits.defaults();
        var ids = Stm32CuratedPartIds.load(SELECTION, limits, CancellationToken.none());
        return Stm32MemoryPlanner.load(MEMORY_PLANS, ids, limits, CancellationToken.none());
    }

    private static Stm32SecurityCatalog security() throws Exception {
        var limits = ParserLimits.defaults();
        var ids = Stm32CuratedPartIds.load(SELECTION, limits, CancellationToken.none());
        return Stm32SecurityCatalog.load(SECURITY_DOMAINS, ids, limits, CancellationToken.none());
    }
}
