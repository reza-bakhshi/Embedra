package io.github.rezabakhshi.embedra.targets.atmel;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.core.io.AddressRange;
import io.github.rezabakhshi.embedra.core.model.Confidence;
import io.github.rezabakhshi.embedra.core.model.Evidence;
import io.github.rezabakhshi.embedra.core.model.EvidenceKind;
import io.github.rezabakhshi.embedra.core.model.ExecutionTopology;
import io.github.rezabakhshi.embedra.core.model.FirmwareSource;
import io.github.rezabakhshi.embedra.core.model.ProcessorKind;
import io.github.rezabakhshi.embedra.core.model.ProcessorNode;
import io.github.rezabakhshi.embedra.core.model.ProgramStrategy;
import io.github.rezabakhshi.embedra.core.model.ResetEntry;
import io.github.rezabakhshi.embedra.core.model.SecurityDomain;
import io.github.rezabakhshi.embedra.core.model.SecurityDomainKind;
import io.github.rezabakhshi.embedra.targets.EntryPointDecision;
import io.github.rezabakhshi.embedra.targets.LanguageSelection;
import io.github.rezabakhshi.embedra.targets.MemoryClassification;
import io.github.rezabakhshi.embedra.targets.MemoryRegionKind;
import io.github.rezabakhshi.embedra.targets.SupportDecision;
import io.github.rezabakhshi.embedra.targets.atmel.catalog.AtmelPartRecord;
import io.github.rezabakhshi.embedra.targets.atmel.memory.AtmelMemoryPlan;
import io.github.rezabakhshi.embedra.targets.atmel.memory.AtmelMemoryPlanner;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Common base class for pure Atmel / Microchip target providers.
 */
public abstract class AbstractAtmelTargetProvider implements AtmelTargetProvider {

    @Override
    public AtmelMemoryPlan planMemory(AtmelPartRecord part, ParserLimits limits, CancellationToken token)
            throws DiagnosticException {
        Objects.requireNonNull(part, "part must not be null");
        SupportDecision decision = supports(part);
        if (!decision.supported()) {
            throw new DiagnosticException(Diagnostic.error(
                DiagnosticCode.ATMEL_TARGET_UNSUPPORTED,
                "Part " + part.exactPart() + " is not supported by " + providerId() + ": " + decision.reason(),
                null));
        }
        return AtmelMemoryPlanner.plan(part, limits, token);
    }

    @Override
    public boolean isAddressMapped(String space, long address, AtmelPartRecord part) {
        try {
            AtmelMemoryPlan plan = AtmelMemoryPlanner.plan(
                part, ParserLimits.defaults(), CancellationToken.none());
            return plan.isMapped(space, address);
        } catch (DiagnosticException e) {
            return false;
        }
    }

    @Override
    public boolean isValidCodeAddress(long address, AtmelPartRecord part) {
        String space = part.isSam() ? "default" : "code";
        long alignedAddress = part.isSam() ? (address & ~1L) : (address & ~1L);
        try {
            AtmelMemoryPlan plan = AtmelMemoryPlanner.plan(
                part, ParserLimits.defaults(), CancellationToken.none());
            return plan.isExecutable(space, alignedAddress);
        } catch (DiagnosticException e) {
            return false;
        }
    }

    @Override
    public EntryPointDecision validateEntry(long address, AtmelPartRecord part) {
        Objects.requireNonNull(part, "part must not be null");
        String space = part.isSam() ? "default" : "code";
        long alignedAddress = part.isSam() ? (address & ~1L) : (address & ~1L);

        if (!isValidCodeAddress(alignedAddress, part)) {
            return new EntryPointDecision(
                false,
                address,
                "Address 0x" + Long.toHexString(address) + " does not fall in executable code region for "
                    + part.exactPart(),
                Optional.empty(),
                List.of(new Evidence(
                    EvidenceKind.DERIVED_RULE,
                    "invalid-code-entry",
                    "Entry address outside valid executable range"))
            );
        }

        if (part.isSam()) {
            boolean thumbBitSet = (address & 1L) != 0L;
            if (!thumbBitSet) {
                return new EntryPointDecision(
                    false,
                    address,
                    "SAM ARM entry address 0x" + Long.toHexString(address) + " requires Thumb mode bit (bit 0 set)",
                    Optional.empty(),
                    List.of(new Evidence(
                        EvidenceKind.DERIVED_RULE,
                        "sam-missing-thumb-bit",
                        "ARM Cortex-M reset handler addresses must have bit 0 set"))
                );
            }
        } else {
            // For AVR, instructions must be 2-byte aligned in code space
            if ((address & 1L) != 0L) {
                return new EntryPointDecision(
                    false,
                    address,
                    "AVR entry address 0x" + Long.toHexString(address) + " must be 2-byte word aligned",
                    Optional.empty(),
                    List.of(new Evidence(
                        EvidenceKind.DERIVED_RULE,
                        "avr-unaligned-entry",
                        "AVR code space instructions are 16-bit word aligned"))
                );
            }
        }

        MemoryClassification classification = new MemoryClassification(
            new AddressRange(space, alignedAddress, 2L),
            MemoryRegionKind.IROM,
            true,
            true,
            false,
            true,
            List.of(new Evidence(
                EvidenceKind.DOCUMENTED_FIELD,
                "atmel-flash",
                "Atmel Code Flash execution"))
        );

        return new EntryPointDecision(
            true,
            address,
            "Valid entry point at 0x" + Long.toHexString(address) + " for " + part.exactPart(),
            Optional.of(classification),
            List.of(new Evidence(
                EvidenceKind.DERIVED_RULE,
                "valid-atmel-entry",
                "Entry point verified within valid executable flash"))
        );
    }

    @Override
    public ExecutionTopology buildTopology(AtmelPartRecord part) {
        Objects.requireNonNull(part, "part must not be null");
        LanguageSelection lang = selectLanguage(part);
        SecurityDomain domain = new SecurityDomain(
            "atmel.standard",
            SecurityDomainKind.NON_SECURE
        );

        String space = part.isSam() ? "default" : "code";
        ResetEntry resetEntry = new ResetEntry(
            "Reset_Handler",
            space,
            part.flashStart(),
            Confidence.VERIFIED,
            List.of(new Evidence(
                EvidenceKind.DOCUMENTED_FIELD,
                "atmel-reset",
                "Reset vector origin"))
        );

        ProcessorNode coreNode = new ProcessorNode(
            part.exactPart() + ".core0",
            ProcessorKind.CPU_CORE,
            Optional.of(part.core()),
            Optional.of(lang.languageId()),
            Optional.of(lang.compilerSpecId()),
            "Main MCU Core",
            domain,
            "Microchip",
            Set.of(space),
            List.of(resetEntry),
            FirmwareSource.INDEPENDENT_IMAGE,
            Confidence.VERIFIED,
            List.of(new Evidence(
                EvidenceKind.DOCUMENTED_FIELD,
                "atmel-core",
                "MCU core architecture"))
        );

        return new ExecutionTopology(
            List.of(coreNode),
            List.of(),
            List.of(),
            List.of(),
            List.of(),
            ProgramStrategy.SHARED_PROGRAM
        );
    }
}
