package io.github.rezabakhshi.embedra.targets.stm8;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.core.model.ExecutionTopology;
import io.github.rezabakhshi.embedra.targets.EntryPointDecision;
import io.github.rezabakhshi.embedra.targets.LanguageSelection;
import io.github.rezabakhshi.embedra.targets.SupportDecision;
import io.github.rezabakhshi.embedra.targets.stm8.catalog.Stm8PartRecord;
import io.github.rezabakhshi.embedra.targets.stm8.memory.Stm8MemoryPlan;

/**
 * Pure contract for STM8 target providers isolating memory layout, execution topology, and ISA selection.
 */
public interface Stm8TargetProvider {

    String providerId();

    String family();

    LanguageSelection selectLanguage(Stm8PartRecord part);

    SupportDecision supports(Stm8PartRecord part);

    Stm8MemoryPlan planMemory(Stm8PartRecord part, ParserLimits limits, CancellationToken token)
            throws DiagnosticException;

    ExecutionTopology buildTopology(Stm8PartRecord part);

    boolean isAddressMapped(long address, Stm8PartRecord part);

    boolean isValidCodeAddress(long address, Stm8PartRecord part);

    EntryPointDecision validateEntry(long address, Stm8PartRecord part);
}
