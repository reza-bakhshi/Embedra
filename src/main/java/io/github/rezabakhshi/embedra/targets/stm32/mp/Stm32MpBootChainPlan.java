package io.github.rezabakhshi.embedra.targets.stm32.mp;

import io.github.rezabakhshi.embedra.core.io.AddressRange;
import io.github.rezabakhshi.embedra.core.model.Confidence;
import io.github.rezabakhshi.embedra.core.model.Evidence;
import io.github.rezabakhshi.embedra.core.model.SecurityDomain;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Validated boot chain plan for an STM32MP heterogeneous processor.
 *
 * <p>Captures the staged handoff from masked ROM code, through First Stage Bootloader
 * (TF-A BL2), Secure Monitor / Secure OS (BL31, OP-TEE BL32), Second Stage Bootloader
 * (U-Boot BL33), operating system (Linux), and remoteproc coprocessor firmware.</p>
 */
public record Stm32MpBootChainPlan(
        String exactPart,
        BootArchitecture architecture,
        List<BootStage> stages,
        Confidence confidence,
        List<Evidence> evidence) {

    public Stm32MpBootChainPlan {
        Objects.requireNonNull(exactPart, "exactPart");
        Objects.requireNonNull(architecture, "architecture");
        Objects.requireNonNull(confidence, "confidence");
        stages = List.copyOf(stages);
        evidence = List.copyOf(evidence);
        if (exactPart.isBlank()) {
            throw new IllegalArgumentException("Exact part must not be blank");
        }
        if (stages.isEmpty()) {
            throw new IllegalArgumentException("Boot chain must have at least one stage");
        }
        Set<String> stageIds = new HashSet<>();
        for (BootStage stage : stages) {
            if (!stageIds.add(stage.id())) {
                throw new IllegalArgumentException("Duplicate boot stage ID: " + stage.id());
            }
        }
    }

    /** Supported boot architecture flavor. */
    public enum BootArchitecture {
        A7_SECURE_BOOT,
        A35_TRUSTED_DOMAIN,
        M33_TRUSTED_DOMAIN
    }

    /** Classification of individual boot chain stages. */
    public enum StageKind {
        ROM,
        FSBL,
        SECURE_MONITOR,
        SECURE_OS,
        SSBL,
        NON_SECURE_OS,
        COPROCESSOR_FIRMWARE
    }

    /** One validated stage within the boot chain. */
    public record BootStage(
            String id,
            StageKind kind,
            String executionUnitId,
            String name,
            String artifactDescription,
            SecurityDomain securityDomain,
            Optional<AddressRange> executionRange,
            Confidence confidence,
            List<Evidence> evidence) {

        public BootStage {
            Objects.requireNonNull(id, "id");
            Objects.requireNonNull(kind, "kind");
            Objects.requireNonNull(executionUnitId, "executionUnitId");
            Objects.requireNonNull(name, "name");
            Objects.requireNonNull(artifactDescription, "artifactDescription");
            Objects.requireNonNull(securityDomain, "securityDomain");
            Objects.requireNonNull(executionRange, "executionRange");
            Objects.requireNonNull(confidence, "confidence");
            evidence = List.copyOf(evidence);
            if (id.isBlank() || executionUnitId.isBlank() || name.isBlank()
                    || artifactDescription.isBlank()) {
                throw new IllegalArgumentException("Boot stage string properties must not be blank");
            }
        }
    }
}
