package io.github.rezabakhshi.embedra.targets.stm8;

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
import io.github.rezabakhshi.embedra.targets.stm8.catalog.Stm8PartRecord;
import io.github.rezabakhshi.embedra.targets.stm8.memory.Stm8MemoryPlan;
import io.github.rezabakhshi.embedra.targets.stm8.memory.Stm8MemoryPlanner;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Common base class for pure STM8 family providers isolating architecture knowledge from STM32.
 */
public abstract class AbstractStm8TargetProvider implements Stm8TargetProvider {

    @Override
    public LanguageSelection selectLanguage(Stm8PartRecord part) {
        Objects.requireNonNull(part, "part must not be null");
        String languageId = part.flashEnd() > 0xFFFFL
            ? "STM8:default:24:default"
            : "STM8:default:16:default";
        int addressBits = part.flashEnd() > 0xFFFFL ? 24 : 16;
        return new LanguageSelection(
            languageId,
            "default",
            "STM8",
            addressBits,
            1,
            "BIG_ENDIAN",
            List.of(new Evidence(
                EvidenceKind.DOCUMENTED_FIELD,
                "stm8-isa",
                "STMicroelectronics STM8 8-bit CISC microcontroller"))
        );
    }

    @Override
    public Stm8MemoryPlan planMemory(Stm8PartRecord part, ParserLimits limits, CancellationToken token)
            throws DiagnosticException {
        Objects.requireNonNull(part, "part must not be null");
        SupportDecision decision = supports(part);
        if (!decision.supported()) {
            throw new DiagnosticException(Diagnostic.error(
                DiagnosticCode.STM8_TARGET_UNSUPPORTED,
                "Part " + part.exactPart() + " is not supported by " + providerId() + ": " + decision.reason(),
                null));
        }
        return Stm8MemoryPlanner.plan(part, limits, token);
    }

    @Override
    public ExecutionTopology buildTopology(Stm8PartRecord part) {
        Objects.requireNonNull(part, "part must not be null");
        LanguageSelection lang = selectLanguage(part);
        SecurityDomain domain = new SecurityDomain("stm8.standard", SecurityDomainKind.NON_SECURE);
        ResetEntry resetEntry = new ResetEntry(
            "Reset_Handler",
            "default",
            0x008000L,
            Confidence.VERIFIED,
            List.of(new Evidence(
                EvidenceKind.DOCUMENTED_FIELD,
                "stm8-reset",
                "Standard STM8 reset vector at 0x008000"))
        );

        ProcessorNode node = new ProcessorNode(
            part.exactPart() + ".core0",
            ProcessorKind.CPU_CORE,
            Optional.of("STM8"),
            Optional.of(lang.languageId()),
            Optional.of(lang.compilerSpecId()),
            "Main Application MCU Core",
            domain,
            "STMicroelectronics",
            Set.of("default"),
            List.of(resetEntry),
            FirmwareSource.INDEPENDENT_IMAGE,
            Confidence.VERIFIED,
            List.of(new Evidence(
                EvidenceKind.DOCUMENTED_FIELD,
                "stm8-core",
                "STM8 8-bit single-core architecture"))
        );

        return new ExecutionTopology(
            List.of(node),
            List.of(),
            List.of(),
            List.of(),
            List.of(),
            ProgramStrategy.SHARED_PROGRAM
        );
    }

    @Override
    public boolean isAddressMapped(long address, Stm8PartRecord part) {
        Objects.requireNonNull(part, "part must not be null");
        if (address < 0 || address > 0xFFFFFFL) {
            return false;
        }
        return (address <= part.ramEnd())
            || (part.eepromBytes() > 0 && address >= part.eepromStart() && address <= part.eepromEnd())
            || (address >= part.optionBytesStart() && address <= part.optionBytesEnd())
            || (address >= part.peripheralsStart() && address <= part.peripheralsEnd())
            || (address >= part.bootRomStart() && address <= part.bootRomEnd())
            || (address >= part.flashStart() && address <= part.flashEnd());
    }

    @Override
    public boolean isValidCodeAddress(long address, Stm8PartRecord part) {
        Objects.requireNonNull(part, "part must not be null");
        return (address >= part.flashStart() && address <= part.flashEnd())
            || (address >= part.bootRomStart() && address <= part.bootRomEnd());
    }

    @Override
    public EntryPointDecision validateEntry(long address, Stm8PartRecord part) {
        Objects.requireNonNull(part, "part must not be null");
        if (!isValidCodeAddress(address, part)) {
            return new EntryPointDecision(
                false,
                address,
                "Address 0x" + Long.toHexString(address) + " is not within executable range for " + part.exactPart(),
                Optional.empty(),
                List.of()
            );
        }
        MemoryClassification classification = new MemoryClassification(
            new AddressRange("default", address, 1L),
            MemoryRegionKind.IROM,

            true,
            true,
            false,
            true,
            List.of(new Evidence(
                EvidenceKind.DOCUMENTED_FIELD,
                "stm8-flash",
                "STM8 on-chip program flash execution"))
        );
        return new EntryPointDecision(
            true,
            address,
            "Valid executable code address in " + part.exactPart(),
            Optional.of(classification),
            List.of()
        );
    }
}
