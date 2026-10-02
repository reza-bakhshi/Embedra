package io.github.rezabakhshi.embedra.targets.stm32.workspace;

import io.github.rezabakhshi.embedra.core.io.AddressRange;
import io.github.rezabakhshi.embedra.core.model.BootRelationship;
import io.github.rezabakhshi.embedra.core.model.BootRelationshipType;
import io.github.rezabakhshi.embedra.core.model.CommunicationKind;
import io.github.rezabakhshi.embedra.core.model.Evidence;
import io.github.rezabakhshi.embedra.core.model.EvidenceKind;
import io.github.rezabakhshi.embedra.core.model.FirmwareSource;
import io.github.rezabakhshi.embedra.core.model.InterProcessorLink;
import io.github.rezabakhshi.embedra.core.model.ProcessorKind;
import io.github.rezabakhshi.embedra.core.model.ProcessorNode;
import io.github.rezabakhshi.embedra.core.model.SharedMemoryRegion;
import io.github.rezabakhshi.embedra.targets.stm32.memory.Stm32MemoryPlanner;
import io.github.rezabakhshi.embedra.targets.stm32.memory.Stm32MemoryPlanner.Region;
import io.github.rezabakhshi.embedra.targets.stm32.security.Stm32SecurityCatalog;
import io.github.rezabakhshi.embedra.targets.stm32.security.Stm32SecurityPlanner;
import io.github.rezabakhshi.embedra.targets.stm32.security.Stm32SecurityRecord;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Composes one exact-part dual-core/heterogeneous workspace plan.
 *
 * <p>The T039 memory plan and the T044 security record are never mutated.
 * Composition fails closed with stable diagnostics on a part mismatch, an
 * unknown configuration input, an unresolved plan configuration, ambiguous or
 * duplicate cores, an undetermined image domain, a region with no pinned core
 * attribution, overlapping program slots, and a missing or ambiguous mailbox,
 * semaphore, or boot-order fact. The curated H7 parts and every other
 * single-core executive return an explicit {@code UNAVAILABLE} plan: no second
 * core or coprocessor image is ever inferred from a family label, a sibling
 * part, or a wildcard reference.</p>
 */
public final class Stm32WorkspacePlanner {
    /** Stable diagnostic codes raised by workspace composition. */
    public enum Diagnostic {
        WORKSPACE_PART_MISMATCH,
        WORKSPACE_CONFIGURATION_UNKNOWN,
        WORKSPACE_PLAN_CONFIGURATION_UNRESOLVED,
        WORKSPACE_IMAGE_DOMAIN_AMBIGUOUS,
        WORKSPACE_IMAGE_DOMAIN_UNDETERMINED,
        WORKSPACE_CORES_AMBIGUOUS,
        WORKSPACE_IMAGE_UNDETERMINED,
        WORKSPACE_MEMORY_UNATTRIBUTED,
        WORKSPACE_SLOT_RANGE_OVERLAP,
        WORKSPACE_BOOT_ORDER_UNPINNED,
        WORKSPACE_BOOT_ORDER_AMBIGUOUS,
        WORKSPACE_MAILBOX_UNPINNED,
        WORKSPACE_SEMAPHORE_UNPINNED,
        WORKSPACE_COMMUNICATION_RANGE_UNPINNED;
    }

    /** A composition failure with a stable diagnostic code. */
    public static final class WorkspacePlanException extends IllegalArgumentException {
        private static final long serialVersionUID = 1L;

        private final Diagnostic diagnostic;

        private WorkspacePlanException(Diagnostic diagnostic, String message) {
            super(message);
            this.diagnostic = diagnostic;
        }

        public Diagnostic diagnostic() {
            return diagnostic;
        }
    }

    /** A program slot id is the pinned core node id plus this suffix. */
    private static final String SLOT_SUFFIX = "-program";

    private Stm32WorkspacePlanner() {
    }

    /** Composes with no workspace configuration input. */
    public static Stm32WorkspacePlan compose(Stm32MemoryPlanner.Plan plan,
            Stm32SecurityRecord securityRecord) {
        return compose(plan, securityRecord, Map.of());
    }

    /**
     * Composes one workspace plan from a validated T039 plan and one T044
     * record for the same exact part.
     *
     * <p>No workspace configuration key is currently pinned, so any supplied
     * input fails closed; a future pinned key would be declared beside its
     * evidence before this contract accepts it.</p>
     *
     * @param configurationInputs explicit configuration keys; unknown keys fail closed
     */
    public static Stm32WorkspacePlan compose(Stm32MemoryPlanner.Plan plan,
            Stm32SecurityRecord securityRecord, Map<String, String> configurationInputs) {
        Objects.requireNonNull(plan, "plan");
        Objects.requireNonNull(securityRecord, "securityRecord");
        Objects.requireNonNull(configurationInputs, "configurationInputs");
        if (!plan.exactPart().equals(securityRecord.exactPart())) {
            throw new WorkspacePlanException(Diagnostic.WORKSPACE_PART_MISMATCH,
                "Security record " + securityRecord.exactPart() + " does not match MCU "
                    + plan.exactPart());
        }
        if (!configurationInputs.isEmpty()) {
            throw new WorkspacePlanException(Diagnostic.WORKSPACE_CONFIGURATION_UNKNOWN,
                "No workspace configuration input is pinned: " + configurationInputs.keySet());
        }
        List<ProcessorNode> cores = plan.topology().processors().stream()
            .filter(node -> node.kind() == ProcessorKind.CPU_CORE)
            .toList();
        if (cores.size() < 2) {
            return unavailable(plan, securityRecord, cores.size());
        }
        return multiCore(plan, securityRecord, cores);
    }

    /** Every single-core executive stays explicit: no invented second core or image. */
    private static Stm32WorkspacePlan unavailable(Stm32MemoryPlanner.Plan plan,
            Stm32SecurityRecord securityRecord, int coreCount) {
        String reason = "SINGLE_CORE_EXECUTION_TOPOLOGY: the validated execution topology declares "
            + coreCount + " executable CPU core(s) and no independently supplied coprocessor "
            + "image for " + plan.exactPart() + "; no second core or coprocessor image exists "
            + "in the pinned sources";
        return new Stm32WorkspacePlan(plan.exactPart(), Stm32WorkspacePlan.Status.UNAVAILABLE,
            reason, plan, securityRecord, null, List.of(), List.of(), evidence());
    }

    private static Stm32WorkspacePlan multiCore(Stm32MemoryPlanner.Plan plan,
            Stm32SecurityRecord securityRecord, List<ProcessorNode> cores) {
        if (!plan.unresolvedConfigurationRegions().isEmpty()) {
            throw new WorkspacePlanException(Diagnostic.WORKSPACE_PLAN_CONFIGURATION_UNRESOLVED,
                "MCU plan has unresolved configuration regions for " + plan.exactPart());
        }
        for (int left = 0; left < cores.size(); left++) {
            for (int right = left + 1; right < cores.size(); right++) {
                ProcessorNode first = cores.get(left);
                ProcessorNode second = cores.get(right);
                if (first.role().equals(second.role())
                        && first.instructionSet().equals(second.instructionSet())) {
                    throw new WorkspacePlanException(Diagnostic.WORKSPACE_CORES_AMBIGUOUS,
                        "CPU cores are not distinguishable for program-slot assignment: "
                            + first.id() + ", " + second.id());
                }
            }
        }
        List<ProcessorNode> primary = cores.stream()
            .filter(node -> node.firmwareSource() == FirmwareSource.SHARED_IMAGE)
            .toList();
        if (primary.size() > 1) {
            throw new WorkspacePlanException(Diagnostic.WORKSPACE_IMAGE_DOMAIN_AMBIGUOUS,
                "More than one core claims the shared device image");
        }
        if (primary.isEmpty()) {
            throw new WorkspacePlanException(Diagnostic.WORKSPACE_IMAGE_DOMAIN_UNDETERMINED,
                "No core carries a pinned shared-image relationship");
        }
        ProcessorNode sharedCore = primary.getFirst();
        List<ProcessorNode> independentCores = cores.stream()
            .filter(node -> node != sharedCore)
            .toList();
        for (ProcessorNode core : independentCores) {
            if (core.firmwareSource() != FirmwareSource.INDEPENDENT_IMAGE) {
                throw new WorkspacePlanException(Diagnostic.WORKSPACE_IMAGE_DOMAIN_UNDETERMINED,
                    "The second core has no pinned independent image: " + core.id());
            }
        }
        List<Region> flashRegions = plan.regions().stream()
            .filter(region -> "FLASH".equals(region.kind()))
            .toList();
        if (flashRegions.size() != 1) {
            throw new WorkspacePlanException(Diagnostic.WORKSPACE_IMAGE_UNDETERMINED,
                "The shared device image requires exactly one pinned FLASH region");
        }
        Region flash = flashRegions.getFirst();
        Map<String, ProcessorNode> coreById = new LinkedHashMap<>();
        for (ProcessorNode core : cores) {
            coreById.put(core.id(), core);
        }
        Map<String, String> slotByCore = new LinkedHashMap<>();
        for (ProcessorNode core : cores) {
            slotByCore.put(core.id(), core.id() + SLOT_SUFFIX);
        }
        validateAttribution(plan, coreById);
        Map<String, BootRelationship> bootByTarget = bootOrder(plan, sharedCore, independentCores);
        Map<String, Stm32WorkspacePlan.ProgramSlot> slots = new LinkedHashMap<>();
        slots.put(sharedCore.id(), slot(sharedCore, plan, flash, true, null, slotByCore));
        for (ProcessorNode core : independentCores) {
            slots.put(core.id(), slot(core, plan, flash, false,
                bootByTarget.get(core.id()).mechanism(), slotByCore));
        }
        validateSharedMemoryBacking(plan, slots.values());
        validateRangesAcrossSlots(slots.values());
        Map<String, List<InterProcessorLink>> mailboxes = pinnedLinks(plan, sharedCore.id(),
            independentCores, CommunicationKind.MAILBOX, Diagnostic.WORKSPACE_MAILBOX_UNPINNED);
        Map<String, List<InterProcessorLink>> semaphores = pinnedLinks(plan, sharedCore.id(),
            independentCores, CommunicationKind.HARDWARE_SEMAPHORE,
            Diagnostic.WORKSPACE_SEMAPHORE_UNPINNED);
        List<Stm32WorkspacePlan.CrossProgramReference> references = new ArrayList<>();
        references.addAll(sharedMemoryReferences(plan.topology().sharedMemories(), slots,
            slotByCore, sharedCore.id()));
        references.addAll(bootReferences(bootByTarget, slotByCore, sharedCore.id()));
        references.addAll(linkReferences(mailboxes, sharedCore.id(),
            Stm32WorkspacePlan.CrossProgramReference.Kind.SHARED_MAILBOX));
        references.addAll(linkReferences(semaphores, sharedCore.id(),
            Stm32WorkspacePlan.CrossProgramReference.Kind.SHARED_SEMAPHORE));
        Stm32SecurityPlanner.SecurityMap securityMap = securityRecord.pinned()
            ? Stm32SecurityPlanner.compose(plan, securityRecord)
            : null;
        List<Stm32WorkspacePlan.ProgramSlot> ordered = new ArrayList<>();
        ordered.add(slots.get(sharedCore.id()));
        for (ProcessorNode core : independentCores) {
            ordered.add(slots.get(core.id()));
        }
        return new Stm32WorkspacePlan(plan.exactPart(), Stm32WorkspacePlan.Status.MULTI_CORE_PINNED,
            null, plan, securityRecord, securityMap, List.copyOf(ordered),
            List.copyOf(references), evidence());
    }

    /** Every core carries pinned memory attribution; non-RAM attribution is rejected. */
    private static void validateAttribution(Stm32MemoryPlanner.Plan plan,
            Map<String, ProcessorNode> coreById) {
        Set<String> attributed = new LinkedHashSet<>();
        for (Region region : plan.regions()) {
            if (region.sharedAccess().isEmpty()) {
                continue;
            }
            if (!"RAM".equals(region.kind())) {
                throw new WorkspacePlanException(Diagnostic.WORKSPACE_MEMORY_UNATTRIBUTED,
                    "A non-RAM region carries core attribution: " + region.id());
            }
            for (String participant : region.sharedAccess().keySet()) {
                if (!coreById.containsKey(participant)) {
                    throw new WorkspacePlanException(Diagnostic.WORKSPACE_MEMORY_UNATTRIBUTED,
                        "Shared-memory participant is not a pinned CPU core: " + participant);
                }
                attributed.add(participant);
            }
        }
        for (String core : coreById.keySet()) {
            if (!attributed.contains(core)) {
                throw new WorkspacePlanException(Diagnostic.WORKSPACE_MEMORY_UNATTRIBUTED,
                    "No pinned region attributes memory to core " + core);
            }
        }
    }

    /** Per-region peers come only from the region's own pinned sharedAccess participants. */
    private static Set<String> viewPeers(Region region, String coreId,
            Map<String, String> slotByCore) {
        Set<String> peers = new LinkedHashSet<>();
        for (String participant : region.sharedAccess().keySet()) {
            if (!participant.equals(coreId)) {
                peers.add(slotByCore.get(participant));
            }
        }
        return peers;
    }

    private static Stm32WorkspacePlan.ProgramSlot slot(ProcessorNode core,
            Stm32MemoryPlanner.Plan plan, Region flash, boolean sharedCore, String bootMechanism,
            Map<String, String> slotByCore) {
        List<Stm32WorkspacePlan.MemoryView> views = new ArrayList<>();
        for (Region region : plan.regions()) {
            if ("FLASH".equals(region.kind())) {
                if (sharedCore) {
                    views.add(new Stm32WorkspacePlan.MemoryView(region.id(), region.kind(),
                        region.range(), region.access(),
                        Stm32WorkspacePlan.MemoryView.Ownership.PRIVATE, Set.of()));
                }
                continue;
            }
            if (!"RAM".equals(region.kind()) || !region.sharedAccess().containsKey(core.id())) {
                continue;
            }
            Set<String> peers = viewPeers(region, core.id(), slotByCore);
            Stm32WorkspacePlan.MemoryView.Ownership ownership = peers.isEmpty()
                ? Stm32WorkspacePlan.MemoryView.Ownership.PRIVATE
                : Stm32WorkspacePlan.MemoryView.Ownership.SHARED;
            views.add(new Stm32WorkspacePlan.MemoryView(region.id(), region.kind(), region.range(),
                region.access(), ownership, peers));
        }
        List<Stm32WorkspacePlan.UnresolvedView> unresolved = List.of();
        if (core.firmwareSource() == FirmwareSource.INDEPENDENT_IMAGE) {
            unresolved = List.of(new Stm32WorkspacePlan.UnresolvedView(core.id() + "-fetch-view",
                "The reset-vector fetch view is configuration-dependent: " + bootMechanism));
        }
        Stm32WorkspacePlan.ImageDomain domain = sharedCore
            ? new Stm32WorkspacePlan.ImageDomain(
                Stm32WorkspacePlan.ImageDomain.State.PINNED_DEVICE_IMAGE, flash.range(), null)
            : new Stm32WorkspacePlan.ImageDomain(
                Stm32WorkspacePlan.ImageDomain.State.UNAVAILABLE_INDEPENDENTLY_SUPPLIED, null,
                "The firmware of " + core.id() + " is supplied independently of the pinned "
                    + "sources and stays unstated; pinned release mechanism: " + bootMechanism);
        return new Stm32WorkspacePlan.ProgramSlot(core.id() + SLOT_SUFFIX, core.id(), core.role(),
            core.firmwareSource(), core.instructionSet().orElseThrow(),
            core.ghidraLanguageId().orElseThrow(), core.compilerSpecId().orElseThrow(),
            core.securityDomain(), domain, views, unresolved);
    }

    /** A shared slot view must reuse the pinned T039 shared-memory backing. */
    private static void validateSharedMemoryBacking(Stm32MemoryPlanner.Plan plan,
            Iterable<Stm32WorkspacePlan.ProgramSlot> slots) {
        for (Stm32WorkspacePlan.ProgramSlot slot : slots) {
            for (Stm32WorkspacePlan.MemoryView view : slot.memoryViews()) {
                if (view.ownership() != Stm32WorkspacePlan.MemoryView.Ownership.SHARED) {
                    continue;
                }
                boolean backed = plan.topology().sharedMemories().stream()
                    .anyMatch(memory -> memory.range().equals(view.range()));
                if (!backed) {
                    throw new WorkspacePlanException(Diagnostic.WORKSPACE_MEMORY_UNATTRIBUTED,
                        "Shared view " + view.regionId() + " has no pinned T039 shared-memory "
                            + "backing");
                }
            }
        }
    }

    /** Slots overlap only at pinned shared ranges that name each other. */
    private static void validateRangesAcrossSlots(
            Iterable<Stm32WorkspacePlan.ProgramSlot> slots) {
        for (Stm32WorkspacePlan.ProgramSlot left : slots) {
            for (Stm32WorkspacePlan.ProgramSlot right : slots) {
                if (left == right) {
                    continue;
                }
                for (Stm32WorkspacePlan.MemoryView first : left.memoryViews()) {
                    for (Stm32WorkspacePlan.MemoryView second : right.memoryViews()) {
                        if (!first.range().overlaps(second.range())) {
                            continue;
                        }
                        boolean documented = first.ownership()
                            == Stm32WorkspacePlan.MemoryView.Ownership.SHARED
                            && second.ownership()
                                == Stm32WorkspacePlan.MemoryView.Ownership.SHARED
                            && first.peerSlotIds().contains(right.id())
                            && second.peerSlotIds().contains(left.id())
                            && first.regionId().equals(second.regionId());
                        if (!documented) {
                            throw new WorkspacePlanException(
                                Diagnostic.WORKSPACE_SLOT_RANGE_OVERLAP,
                                "Program slots " + left.id() + " and " + right.id()
                                    + " overlap outside a documented shared range: "
                                    + left.nodeId() + "/" + first.regionId());
                        }
                    }
                }
            }
        }
    }

    /** Each independently supplied core needs exactly one pinned release order. */
    private static Map<String, BootRelationship> bootOrder(Stm32MemoryPlanner.Plan plan,
            ProcessorNode sharedCore, List<ProcessorNode> independentCores) {
        Map<String, BootRelationship> byTarget = new LinkedHashMap<>();
        for (BootRelationship relationship : plan.topology().bootRelationships()) {
            if (relationship.type() != BootRelationshipType.RELEASES_FROM_RESET) {
                continue;
            }
            if (!relationship.sourceNodeId().equals(sharedCore.id())) {
                continue;
            }
            String target = relationship.targetNodeId();
            if (independentCores.stream().noneMatch(core -> core.id().equals(target))) {
                throw new WorkspacePlanException(Diagnostic.WORKSPACE_BOOT_ORDER_UNPINNED,
                    "Release order targets a core without a pinned independent image: " + target);
            }
            if (byTarget.putIfAbsent(target, relationship) != null) {
                throw new WorkspacePlanException(Diagnostic.WORKSPACE_BOOT_ORDER_AMBIGUOUS,
                    "More than one pinned release order targets " + target);
            }
        }
        for (ProcessorNode core : independentCores) {
            if (!byTarget.containsKey(core.id())) {
                throw new WorkspacePlanException(Diagnostic.WORKSPACE_BOOT_ORDER_UNPINNED,
                    "No pinned release order releases " + core.id());
            }
        }
        return byTarget;
    }

    /** Collects the pinned per-core mailbox/semaphore links and their ranges. */
    private static Map<String, List<InterProcessorLink>> pinnedLinks(
            Stm32MemoryPlanner.Plan plan, String sharedCoreId, List<ProcessorNode> independentCores,
            CommunicationKind kind, Diagnostic unpinDiagnostic) {
        Map<String, List<InterProcessorLink>> pinned = new LinkedHashMap<>();
        for (ProcessorNode core : independentCores) {
            List<InterProcessorLink> matches = plan.topology().communicationLinks().stream()
                .filter(link -> link.kind() == kind
                    && link.participantNodeIds().contains(sharedCoreId)
                    && link.participantNodeIds().contains(core.id()))
                .toList();
            if (matches.isEmpty()) {
                throw new WorkspacePlanException(unpinDiagnostic,
                    "No pinned " + kind + " link covers " + sharedCoreId + " and " + core.id());
            }
            List<InterProcessorLink> links = new ArrayList<>();
            for (InterProcessorLink link : matches) {
                if (link.registerRange().isEmpty()) {
                    throw new WorkspacePlanException(
                        Diagnostic.WORKSPACE_COMMUNICATION_RANGE_UNPINNED,
                        "Communication link has no pinned register range: " + link.id());
                }
                if (!links.contains(link)) {
                    links.add(link);
                }
            }
            pinned.put(core.id(), links);
        }
        return Map.copyOf(pinned);
    }

    private static List<Stm32WorkspacePlan.CrossProgramReference> sharedMemoryReferences(
            List<SharedMemoryRegion> memories, Map<String, Stm32WorkspacePlan.ProgramSlot> slots,
            Map<String, String> slotByCore, String sharedCoreId) {
        List<Stm32WorkspacePlan.CrossProgramReference> references = new ArrayList<>();
        String sharedSlotId = slots.get(sharedCoreId).id();
        for (SharedMemoryRegion memory : memories) {
            LinkedHashSet<String> covered = new LinkedHashSet<>();
            for (String coreId : slotByCore.keySet()) {
                if (memory.referencedProcessorIds().contains(coreId)) {
                    covered.add(slotByCore.get(coreId));
                }
            }
            if (covered.size() < 2) {
                continue;
            }
            List<AddressRange> ranges = new ArrayList<>();
            ranges.add(memory.range());
            ranges.addAll(memory.aliases());
            String mechanism = "shared memory " + memory.id() + " readers "
                + memory.readerNodeIds() + " writers " + memory.writerNodeIds();
            for (String slotId : covered) {
                if (slotId.equals(sharedSlotId)) {
                    continue;
                }
                references.add(new Stm32WorkspacePlan.CrossProgramReference(memory.id() + ":"
                    + slotId, Stm32WorkspacePlan.CrossProgramReference.Kind.SHARED_MEMORY,
                    sharedSlotId, slotId, ranges, mechanism, memory.confidence(),
                    memory.evidence()));
            }
        }
        return references;
    }

    private static List<Stm32WorkspacePlan.CrossProgramReference> bootReferences(
            Map<String, BootRelationship> bootByTarget, Map<String, String> slotByCore,
            String sharedCoreId) {
        List<Stm32WorkspacePlan.CrossProgramReference> references = new ArrayList<>();
        for (Map.Entry<String, BootRelationship> entry : bootByTarget.entrySet()) {
            references.add(new Stm32WorkspacePlan.CrossProgramReference(
                "boot-" + entry.getValue().id(),
                Stm32WorkspacePlan.CrossProgramReference.Kind.BOOT_HANDOFF,
                slotByCore.get(sharedCoreId), slotByCore.get(entry.getKey()), List.of(),
                entry.getValue().mechanism(), entry.getValue().confidence(),
                entry.getValue().evidence()));
        }
        return references;
    }

    private static List<Stm32WorkspacePlan.CrossProgramReference> linkReferences(
            Map<String, List<InterProcessorLink>> pinned, String sharedCoreId,
            Stm32WorkspacePlan.CrossProgramReference.Kind referenceKind) {
        List<Stm32WorkspacePlan.CrossProgramReference> references = new ArrayList<>();
        for (Map.Entry<String, List<InterProcessorLink>> entry : pinned.entrySet()) {
            for (InterProcessorLink link : entry.getValue()) {
                references.add(new Stm32WorkspacePlan.CrossProgramReference(link.id() + ":"
                    + slotSuffix(entry.getKey()), referenceKind,
                    sharedCoreId + SLOT_SUFFIX, entry.getKey() + SLOT_SUFFIX,
                    List.of(link.registerRange().orElseThrow()),
                    link.id() + ": shared " + link.kind() + " registers",
                    link.confidence(), link.evidence()));
            }
        }
        return references;
    }

    private static String slotSuffix(String coreId) {
        return coreId + SLOT_SUFFIX;
    }

    private static List<Evidence> evidence() {
        return List.of(
            new Evidence(EvidenceKind.VERIFIED_CHECKSUM,
                "stm32.workspace:memory-plans:" + Stm32MemoryPlanner.CATALOG_SHA256,
                "Core roles, shared memory, mailboxes, semaphores, and boot order reuse the "
                    + "digest-pinned T039 plan without mutation"),
            new Evidence(EvidenceKind.VERIFIED_CHECKSUM,
                "stm32.workspace:security-domains:" + Stm32SecurityCatalog.SHA256,
                "TrustZone attribution comes only from the digest-pinned T044 record for the "
                    + "same exact part"));
    }
}
