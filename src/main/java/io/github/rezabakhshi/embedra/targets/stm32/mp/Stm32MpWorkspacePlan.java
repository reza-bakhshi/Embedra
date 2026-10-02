package io.github.rezabakhshi.embedra.targets.stm32.mp;

import io.github.rezabakhshi.embedra.core.io.AddressRange;
import io.github.rezabakhshi.embedra.core.model.Confidence;
import io.github.rezabakhshi.embedra.core.model.Evidence;
import io.github.rezabakhshi.embedra.core.model.FirmwareSource;
import io.github.rezabakhshi.embedra.core.model.SecurityDomain;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Multi-program workspace plan for STM32MP heterogeneous systems per TOPO-004.
 *
 * <p>Separates distinct ISAs, operating system runtimes, and security domains into
 * dedicated Ghidra program slots, interlinked with typed cross-program references.</p>
 */
public record Stm32MpWorkspacePlan(
        String exactPart,
        List<ProgramSlot> programSlots,
        List<CrossProgramReference> crossProgramReferences,
        Confidence confidence,
        List<Evidence> evidence) {

    public Stm32MpWorkspacePlan {
        Objects.requireNonNull(exactPart, "exactPart");
        Objects.requireNonNull(confidence, "confidence");
        programSlots = List.copyOf(programSlots);
        crossProgramReferences = List.copyOf(crossProgramReferences);
        evidence = List.copyOf(evidence);

        if (exactPart.isBlank()) {
            throw new IllegalArgumentException("Exact part must not be blank");
        }
        if (programSlots.isEmpty()) {
            throw new IllegalArgumentException("Workspace plan must have at least one program slot");
        }
        Set<String> slotIds = new HashSet<>();
        for (ProgramSlot slot : programSlots) {
            if (!slotIds.add(slot.id())) {
                throw new IllegalArgumentException("Duplicate program slot ID: " + slot.id());
            }
        }
        Set<String> refIds = new HashSet<>();
        for (CrossProgramReference ref : crossProgramReferences) {
            if (!refIds.add(ref.id())) {
                throw new IllegalArgumentException("Duplicate cross-program reference ID: " + ref.id());
            }
            if (ref.sourceSlotId().equals(ref.targetSlotId())) {
                throw new IllegalArgumentException("Cross-program reference cannot self-loop: " + ref.id());
            }
            if (!slotIds.contains(ref.sourceSlotId()) || !slotIds.contains(ref.targetSlotId())) {
                throw new IllegalArgumentException("Cross-program reference connects unknown slot: " + ref.id());
            }
        }
    }

    /** Classification of cross-program relationships between slots. */
    public enum ReferenceKind {
        BOOT_HANDOFF,
        SHARED_MAILBOX,
        SHARED_SEMAPHORE,
        SHARED_MEMORY,
        DEVICETREE_BINDING
    }

    /** Planned Ghidra program representing one execution unit or security domain. */
    public record ProgramSlot(
            String id,
            String nodeId,
            String role,
            FirmwareSource firmwareSource,
            String instructionSet,
            String ghidraLanguageId,
            String compilerSpecId,
            SecurityDomain securityDomain,
            Optional<AddressRange> plannedRange,
            Confidence confidence,
            List<Evidence> evidence) {

        public ProgramSlot {
            Objects.requireNonNull(id, "id");
            Objects.requireNonNull(nodeId, "nodeId");
            Objects.requireNonNull(role, "role");
            Objects.requireNonNull(firmwareSource, "firmwareSource");
            Objects.requireNonNull(instructionSet, "instructionSet");
            Objects.requireNonNull(ghidraLanguageId, "ghidraLanguageId");
            Objects.requireNonNull(compilerSpecId, "compilerSpecId");
            Objects.requireNonNull(securityDomain, "securityDomain");
            Objects.requireNonNull(plannedRange, "plannedRange");
            Objects.requireNonNull(confidence, "confidence");
            evidence = List.copyOf(evidence);
            if (id.isBlank() || nodeId.isBlank() || role.isBlank()
                    || instructionSet.isBlank() || ghidraLanguageId.isBlank()
                    || compilerSpecId.isBlank()) {
                throw new IllegalArgumentException("Program slot string fields must not be blank");
            }
        }
    }

    /** Typed semantic reference connecting two distinct program slots. */
    public record CrossProgramReference(
            String id,
            ReferenceKind kind,
            String sourceSlotId,
            String targetSlotId,
            Optional<AddressRange> sharedRange,
            String description,
            Confidence confidence,
            List<Evidence> evidence) {

        public CrossProgramReference {
            Objects.requireNonNull(id, "id");
            Objects.requireNonNull(kind, "kind");
            Objects.requireNonNull(sourceSlotId, "sourceSlotId");
            Objects.requireNonNull(targetSlotId, "targetSlotId");
            Objects.requireNonNull(sharedRange, "sharedRange");
            Objects.requireNonNull(description, "description");
            Objects.requireNonNull(confidence, "confidence");
            evidence = List.copyOf(evidence);
            if (id.isBlank() || sourceSlotId.isBlank() || targetSlotId.isBlank() || description.isBlank()) {
                throw new IllegalArgumentException("Cross-program reference fields must not be blank");
            }
        }
    }
}
