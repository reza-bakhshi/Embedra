package io.github.rezabakhshi.embedra.targets.stm32.workspace;

import io.github.rezabakhshi.embedra.core.io.AddressRange;
import io.github.rezabakhshi.embedra.core.model.Confidence;
import io.github.rezabakhshi.embedra.core.model.Evidence;
import io.github.rezabakhshi.embedra.core.model.FirmwareSource;
import io.github.rezabakhshi.embedra.core.model.SecurityDomain;
import io.github.rezabakhshi.embedra.targets.stm32.memory.Stm32MemoryPlanner;
import io.github.rezabakhshi.embedra.targets.stm32.security.Stm32SecurityPlanner;
import io.github.rezabakhshi.embedra.targets.stm32.security.Stm32SecurityRecord;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * Immutable dual-core/heterogeneous workspace plan for one exact curated part.
 *
 * <p>The plan references a validated T039 memory plan and a T044 security
 * record for the same exact part without mutating either. A
 * {@code MULTI_CORE_PINNED} plan carries one {@link ProgramSlot} per
 * independently supplied executable domain and typed cross-program references;
 * an {@code UNAVAILABLE} plan carries only a reason. Every current record
 * keeps its curated {@code PLANNED} support state.</p>
 */
public record Stm32WorkspacePlan(
        String exactPart,
        Status status,
        String reason,
        Stm32MemoryPlanner.Plan mcuPlan,
        Stm32SecurityRecord securityRecord,
        Stm32SecurityPlanner.SecurityMap securityMap,
        List<ProgramSlot> programs,
        List<CrossProgramReference> crossProgramReferences,
        List<Evidence> evidence) {

    /** Workspace evidence state; unavailable facts stay explicit with a reason. */
    public enum Status {
        MULTI_CORE_PINNED, UNAVAILABLE
    }

    /**
     * One independently supplied executable domain.
     *
     * @param id the unique image-domain slot id, derived from the core node id
     * @param nodeId the pinned T039 processor node the slot plans
     * @param imageDomain the pinned device image or the explicit unavailability
     * @param memoryViews the per-core memory attribution from pinned evidence
     * @param unresolvedViews the explicitly unresolved configuration-dependent views
     */
    public record ProgramSlot(String id, String nodeId, String role,
            FirmwareSource firmwareSource, String instructionSet, String ghidraLanguageId,
            String compilerSpecId, SecurityDomain securityDomain, ImageDomain imageDomain,
            List<MemoryView> memoryViews, List<UnresolvedView> unresolvedViews) {
        public ProgramSlot {
            Objects.requireNonNull(id, "id");
            Objects.requireNonNull(nodeId, "nodeId");
            Objects.requireNonNull(role, "role");
            Objects.requireNonNull(firmwareSource, "firmwareSource");
            Objects.requireNonNull(securityDomain, "securityDomain");
            Objects.requireNonNull(imageDomain, "imageDomain");
            Objects.requireNonNull(instructionSet, "instructionSet");
            Objects.requireNonNull(ghidraLanguageId, "ghidraLanguageId");
            Objects.requireNonNull(compilerSpecId, "compilerSpecId");
            memoryViews = List.copyOf(memoryViews);
            unresolvedViews = List.copyOf(unresolvedViews);
            if (id.isBlank() || nodeId.isBlank() || role.isBlank()
                    || instructionSet.isBlank() || ghidraLanguageId.isBlank()
                    || compilerSpecId.isBlank()) {
                throw new IllegalArgumentException("Program-slot identity is incomplete");
            }
            if (firmwareSource != FirmwareSource.SHARED_IMAGE
                    && firmwareSource != FirmwareSource.INDEPENDENT_IMAGE) {
                throw new IllegalArgumentException(
                    "A program slot requires a pinned image relationship");
            }
            if (memoryViews.isEmpty()) {
                throw new IllegalArgumentException("A program slot requires pinned memory views");
            }
            Set<String> viewIds = new HashSet<>();
            for (int left = 0; left < memoryViews.size(); left++) {
                if (!viewIds.add(memoryViews.get(left).regionId())) {
                    throw new IllegalArgumentException("Duplicate program-slot memory view");
                }
                for (int right = left + 1; right < memoryViews.size(); right++) {
                    if (memoryViews.get(left).range().overlaps(memoryViews.get(right).range())) {
                        throw new IllegalArgumentException("Overlapping program-slot memory views");
                    }
                }
            }
            Set<String> unresolvedIds = new HashSet<>();
            for (UnresolvedView view : unresolvedViews) {
                if (!unresolvedIds.add(view.id())) {
                    throw new IllegalArgumentException("Duplicate program-slot unresolved view");
                }
            }
        }

        /** True when this slot shares at least one pinned memory range. */
        public boolean sharesMemory() {
            return memoryViews.stream()
                .anyMatch(view -> view.ownership() == MemoryView.Ownership.SHARED);
        }
    }

    /**
     * The image relationship of one program slot.
     *
     * <p>{@code PINNED_DEVICE_IMAGE} carries the reviewed plan region range the
     * supplied image occupies. {@code UNAVAILABLE_INDEPENDENTLY_SUPPLIED}
     * records that the bytes are supplied separately and are never invented;
     * no fabricated range, size, or address is attached.</p>
     */
    public record ImageDomain(State state, AddressRange range, String reason) {
        /** Whether a pinned image exists for the program slot. */
        public enum State {
            PINNED_DEVICE_IMAGE, UNAVAILABLE_INDEPENDENTLY_SUPPLIED
        }

        public ImageDomain {
            Objects.requireNonNull(state, "state");
            if (state == State.PINNED_DEVICE_IMAGE) {
                if (range == null || reason != null) {
                    throw new IllegalArgumentException(
                        "A pinned image domain requires a range and no reason");
                }
            }
            else {
                if (range != null || reason == null || reason.isBlank()) {
                    throw new IllegalArgumentException(
                        "An unavailable image domain requires a reason and no range");
                }
            }
        }
    }

    /**
     * Per-core memory attribution for one plan region.
     *
     * <p>{@code SHARED} views name the other program slots that the pinned
     * {@code sharedAccess} evidence admits; {@code PRIVATE} views carry no
     * peers. Only pinned shared or single-core facts can attribute a region.</p>
     */
    public record MemoryView(String regionId, String kind, AddressRange range, String access,
            Ownership ownership, Set<String> peerSlotIds) {
        /** Whether the pinned evidence shares the region across program slots. */
        public enum Ownership {
            PRIVATE, SHARED
        }

        public MemoryView {
            Objects.requireNonNull(regionId, "regionId");
            Objects.requireNonNull(kind, "kind");
            Objects.requireNonNull(range, "range");
            Objects.requireNonNull(access, "access");
            Objects.requireNonNull(ownership, "ownership");
            Objects.requireNonNull(peerSlotIds, "peerSlotIds");
            peerSlotIds = Set.copyOf(peerSlotIds);
            if (regionId.isBlank() || kind.isBlank() || access.isBlank()) {
                throw new IllegalArgumentException("Memory-view identity is incomplete");
            }
            if (range.length() <= 0 || range.endExclusive() > 0x1_0000_0000L) {
                throw new IllegalArgumentException("Memory view must fit the 32-bit address space");
            }
            if (ownership == Ownership.SHARED && peerSlotIds.isEmpty()) {
                throw new IllegalArgumentException("A shared memory view requires peer slots");
            }
            if (ownership == Ownership.PRIVATE && !peerSlotIds.isEmpty()) {
                throw new IllegalArgumentException("A private memory view must carry no peers");
            }
        }
    }

    /** An explicitly unresolved configuration-dependent memory view. */
    public record UnresolvedView(String id, String reason) {
        public UnresolvedView {
            Objects.requireNonNull(id, "id");
            Objects.requireNonNull(reason, "reason");
            if (id.isBlank() || reason.isBlank()) {
                throw new IllegalArgumentException("Unresolved view identity is incomplete");
            }
        }
    }

    /**
     * One typed cross-program reference with provenance.
     *
     * <p>A {@code BOOT_HANDOFF} cites the pinned boot-order mechanism and
     * carries no address range; every {@code SHARED_*} kind carries the pinned
     * shared register or memory ranges that link the two program slots.</p>
     */
    public record CrossProgramReference(String id, Kind kind, String fromSlotId,
            String toSlotId, List<AddressRange> sharedRanges, String mechanism,
            Confidence confidence, List<Evidence> evidence) {
        /** The pinned navigation relationship between two program slots. */
        public enum Kind {
            BOOT_HANDOFF, SHARED_MAILBOX, SHARED_SEMAPHORE, SHARED_MEMORY
        }

        public CrossProgramReference {
            Objects.requireNonNull(id, "id");
            Objects.requireNonNull(kind, "kind");
            Objects.requireNonNull(mechanism, "mechanism");
            Objects.requireNonNull(confidence, "confidence");
            sharedRanges = List.copyOf(sharedRanges);
            evidence = List.copyOf(evidence);
            if (id.isBlank() || mechanism.isBlank()) {
                throw new IllegalArgumentException("Cross-program reference identity is incomplete");
            }
            if (kind == Kind.BOOT_HANDOFF) {
                if (!sharedRanges.isEmpty()) {
                    throw new IllegalArgumentException(
                        "A boot handoff carries a mechanism, not an invented range");
                }
            }
            else if (sharedRanges.isEmpty()) {
                throw new IllegalArgumentException(
                    "A shared cross-program reference requires pinned ranges");
            }
            if (sharedRanges.stream().anyMatch(range -> range == null || range.length() <= 0
                    || range.endExclusive() > 0x1_0000_0000L)) {
                throw new IllegalArgumentException(
                    "Cross-program ranges must fit the 32-bit address space");
            }
            if (evidence.isEmpty()) {
                throw new IllegalArgumentException("Cross-program references require evidence");
            }
        }
    }

    public Stm32WorkspacePlan {
        Objects.requireNonNull(exactPart, "exactPart");
        Objects.requireNonNull(status, "status");
        Objects.requireNonNull(mcuPlan, "mcuPlan");
        Objects.requireNonNull(securityRecord, "securityRecord");
        programs = List.copyOf(programs);
        crossProgramReferences = List.copyOf(crossProgramReferences);
        evidence = List.copyOf(evidence);
        if (exactPart.isBlank()) {
            throw new IllegalArgumentException("Workspace plan requires an exact part");
        }
        Set<String> slotIds = new HashSet<>();
        Set<String> slotNodes = new HashSet<>();
        for (ProgramSlot slot : programs) {
            if (!slotIds.add(slot.id()) || !slotNodes.add(slot.nodeId())) {
                throw new IllegalArgumentException("Duplicate program slot");
            }
        }
        Set<String> referenceIds = new HashSet<>();
        for (CrossProgramReference reference : crossProgramReferences) {
            if (!referenceIds.add(reference.id())) {
                throw new IllegalArgumentException("Duplicate cross-program reference");
            }
            if (!slotIds.contains(reference.fromSlotId()) || !slotIds.contains(reference.toSlotId())) {
                throw new IllegalArgumentException(
                    "Cross-program reference names an unknown program slot");
            }
            if (reference.fromSlotId().equals(reference.toSlotId())) {
                throw new IllegalArgumentException(
                    "A cross-program reference requires two distinct program slots");
            }
        }
        for (ProgramSlot slot : programs) {
            for (MemoryView view : slot.memoryViews()) {
                for (String peer : view.peerSlotIds()) {
                    if (!slotIds.contains(peer)) {
                        throw new IllegalArgumentException(
                            "A shared memory view names an unknown program slot");
                    }
                }
            }
        }
        if (status == Status.MULTI_CORE_PINNED) {
            if (reason != null) {
                throw new IllegalArgumentException(
                    "A pinned workspace plan must not carry a reason");
            }
            if (programs.isEmpty() || crossProgramReferences.isEmpty()) {
                throw new IllegalArgumentException(
                    "A pinned workspace plan requires program slots and cross-program references");
            }
        }
        else {
            if (reason == null || reason.isBlank()) {
                throw new IllegalArgumentException("An unavailable workspace plan requires a reason");
            }
            if (!programs.isEmpty() || !crossProgramReferences.isEmpty() || securityMap != null) {
                throw new IllegalArgumentException(
                    "An unavailable workspace plan must not carry program or security data");
            }
        }
    }

    /** True when this exact part has a pinned multi-core workspace. */
    public boolean pinned() {
        return status == Status.MULTI_CORE_PINNED;
    }

    /** Every exact STM32 part remains PLANNED; workspace planning never promotes. */
    public String supportState() {
        return "PLANNED";
    }
}
