package io.github.rezabakhshi.embedra.targets.atmel;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.core.model.ExecutionTopology;
import io.github.rezabakhshi.embedra.targets.EntryPointDecision;
import io.github.rezabakhshi.embedra.targets.LanguageSelection;
import io.github.rezabakhshi.embedra.targets.SupportDecision;
import io.github.rezabakhshi.embedra.targets.atmel.catalog.AtmelPartRecord;
import io.github.rezabakhshi.embedra.targets.atmel.memory.AtmelMemoryPlan;

/**
 * Pure contract for Atmel / Microchip target providers isolating architecture, memory layout, and ISA selection.
 */
public interface AtmelTargetProvider {

    String providerId();

    String series();

    String family();

    LanguageSelection selectLanguage(AtmelPartRecord part);

    SupportDecision supports(AtmelPartRecord part);

    AtmelMemoryPlan planMemory(AtmelPartRecord part, ParserLimits limits, CancellationToken token)
            throws DiagnosticException;

    ExecutionTopology buildTopology(AtmelPartRecord part);

    boolean isAddressMapped(String space, long address, AtmelPartRecord part);

    boolean isValidCodeAddress(long address, AtmelPartRecord part);

    EntryPointDecision validateEntry(long address, AtmelPartRecord part);
}
