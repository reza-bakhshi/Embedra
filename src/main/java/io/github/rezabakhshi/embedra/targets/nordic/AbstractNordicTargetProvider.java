package io.github.rezabakhshi.embedra.targets.nordic;

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
import io.github.rezabakhshi.embedra.targets.nordic.catalog.NordicPartRecord;
import io.github.rezabakhshi.embedra.targets.nordic.memory.NordicMemoryPlan;
import io.github.rezabakhshi.embedra.targets.nordic.memory.NordicMemoryPlanner;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Common base class for pure Nordic Semiconductor family target providers.
 */
public abstract class AbstractNordicTargetProvider implements NordicTargetProvider {

    @Override
    public NordicMemoryPlan planMemory(NordicPartRecord part, ParserLimits limits, CancellationToken token)
            throws DiagnosticException {
        Objects.requireNonNull(part, "part must not be null");
        SupportDecision decision = supports(part);
        if (!decision.supported()) {
            throw new DiagnosticException(Diagnostic.error(
                DiagnosticCode.NORDIC_TARGET_UNSUPPORTED,
                "Part " + part.exactPart() + " is not supported by " + providerId() + ": " + decision.reason(),
                null));
        }
        return NordicMemoryPlanner.plan(part, limits, token);
    }

    @Override
    public boolean isAddressMapped(long address, NordicPartRecord part) {
        try {
            NordicMemoryPlan plan = NordicMemoryPlanner.plan(
                part, ParserLimits.defaults(), CancellationToken.none());
            return plan.isMapped(address);
        } catch (DiagnosticException e) {
            return false;
        }
    }

    @Override
    public boolean isValidCodeAddress(long address, NordicPartRecord part) {
        long alignedAddress = address & ~1L;
        try {
            NordicMemoryPlan plan = NordicMemoryPlanner.plan(
                part, ParserLimits.defaults(), CancellationToken.none());
            return plan.isExecutable(alignedAddress);
        } catch (DiagnosticException e) {
            return false;
        }
    }

    @Override
    public EntryPointDecision validateEntry(long address, NordicPartRecord part) {
        Objects.requireNonNull(part, "part must not be null");
        long alignedAddress = address & ~1L;
        if (!isValidCodeAddress(alignedAddress, part)) {
            return new EntryPointDecision(
                false,
                address,
                "Address 0x" + Long.toHexString(address) + " does not fall in executable code region for "
                    + part.exactPart(),
                Optional.empty(),
                List.of(new Evidence(
                    EvidenceKind.DERIVED_RULE,
                    "invalid-cortex-m-entry",
                    "Entry address outside valid executable range"))
            );
        }
        boolean thumbBitSet = (address & 1L) != 0L;
        MemoryClassification classification = new MemoryClassification(
            new AddressRange("default", alignedAddress, 1L),
            MemoryRegionKind.IROM,
            true,
            true,
            false,
            true,
            List.of(new Evidence(
                EvidenceKind.DOCUMENTED_FIELD,
                "nordic-flash",
                "Nordic Code Flash on-chip execution"))
        );
        return new EntryPointDecision(
            true,
            address,
            thumbBitSet ? "Valid Cortex-M Thumb entry point" : "Entry point address (Thumb bit cleared)",
            Optional.of(classification),
            List.of(new Evidence(
                EvidenceKind.DOCUMENTED_FIELD,
                "cortex-m-entry",
                "Executable address within " + part.exactPart() + " Code Flash"))
        );
    }

    @Override
    public ExecutionTopology buildTopology(NordicPartRecord part) {
        Objects.requireNonNull(part, "part must not be null");
        LanguageSelection lang = selectLanguage(part);
        SecurityDomain domain = new SecurityDomain(
            part.trustZone() ? "nordic.trustzone.secure" : "nordic.standard",
            part.trustZone() ? SecurityDomainKind.SECURE : SecurityDomainKind.NON_SECURE
        );

        ResetEntry resetEntry = new ResetEntry(
            "Reset_Handler",
            "default",
            0x00000000L,
            Confidence.VERIFIED,
            List.of(new Evidence(
                EvidenceKind.DOCUMENTED_FIELD,
                "nordic-reset",
                "Standard Cortex-M vector table origin at 0x00000000"))
        );

        ProcessorNode appNode = new ProcessorNode(
            part.exactPart() + ".core0",
            ProcessorKind.CPU_CORE,
            Optional.of(part.core()),
            Optional.of(lang.languageId()),
            Optional.of(lang.compilerSpecId()),
            part.dualCore() ? "Application MCU Core" : "Main MCU Core",
            domain,
            "Nordic Semiconductor",
            Set.of("default"),
            List.of(resetEntry),
            FirmwareSource.INDEPENDENT_IMAGE,
            Confidence.VERIFIED,
            List.of(new Evidence(
                EvidenceKind.DOCUMENTED_FIELD,
                "nordic-core",
                "Nordic MCU architecture"))
        );

        List<ProcessorNode> nodes = new ArrayList<>();
        nodes.add(appNode);

        if (part.dualCore() && part.series().equalsIgnoreCase("nRF53")) {
            SecurityDomain netDomain = new SecurityDomain("nordic.network", SecurityDomainKind.NON_SECURE);
            ProcessorNode netNode = new ProcessorNode(
                part.exactPart() + ".core1",
                ProcessorKind.CPU_CORE,
                Optional.of("ARM Cortex-M33"),
                Optional.of("ARM:LE:32:v8M"),
                Optional.of("default"),
                "Network MCU Core",
                netDomain,
                "Nordic Semiconductor",
                Set.of("default"),
                List.of(new ResetEntry(
                    "Reset_Handler",
                    "default",
                    0x01000000L,
                    Confidence.VERIFIED,
                    List.of(new Evidence(
                        EvidenceKind.DOCUMENTED_FIELD,
                        "nordic-net-reset",
                        "Network core reset vector"))
                )),
                FirmwareSource.INDEPENDENT_IMAGE,
                Confidence.VERIFIED,
                List.of(new Evidence(
                    EvidenceKind.DOCUMENTED_FIELD,
                    "nordic-net-core",
                    "Network MCU architecture"))
            );
            nodes.add(netNode);
        }

        return new ExecutionTopology(
            nodes,
            List.of(),
            List.of(),
            List.of(),
            List.of(),
            ProgramStrategy.SHARED_PROGRAM
        );
    }
}
