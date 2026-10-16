package io.github.rezabakhshi.embedra.targets.nordic;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.core.model.ExecutionTopology;
import io.github.rezabakhshi.embedra.targets.EntryPointDecision;
import io.github.rezabakhshi.embedra.targets.LanguageSelection;
import io.github.rezabakhshi.embedra.targets.SupportDecision;
import io.github.rezabakhshi.embedra.targets.nordic.catalog.NordicPartRecord;
import io.github.rezabakhshi.embedra.targets.nordic.memory.NordicMemoryPlan;

/**
 * Pure contract for Nordic target providers isolating memory layout, execution topology, and ISA selection.
 */
public interface NordicTargetProvider {

    String providerId();

    String series();

    LanguageSelection selectLanguage(NordicPartRecord part);

    SupportDecision supports(NordicPartRecord part);

    NordicMemoryPlan planMemory(NordicPartRecord part, ParserLimits limits, CancellationToken token)
            throws DiagnosticException;

    ExecutionTopology buildTopology(NordicPartRecord part);

    boolean isAddressMapped(long address, NordicPartRecord part);

    boolean isValidCodeAddress(long address, NordicPartRecord part);

    EntryPointDecision validateEntry(long address, NordicPartRecord part);
}
