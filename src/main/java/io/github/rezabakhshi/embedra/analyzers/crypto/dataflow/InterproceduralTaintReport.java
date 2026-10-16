package io.github.rezabakhshi.embedra.analyzers.crypto.dataflow;

import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoFinding;
import java.util.Collections;
import java.util.List;
import java.util.Set;

/**
 * Immutable report summarizing interprocedural taint analysis and verified dataflow paths.
 */
public record InterproceduralTaintReport(
        List<TaintPropagationPath> verifiedPaths,
        Set<String> taintedFunctions,
        int totalSources,
        int totalSinks,
        int maxDepthReached,
        List<CryptoFinding> correlatedFindings) {

    public InterproceduralTaintReport {
        verifiedPaths = verifiedPaths == null
                ? List.of() : Collections.unmodifiableList(List.copyOf(verifiedPaths));
        taintedFunctions = taintedFunctions == null
                ? Set.of() : Collections.unmodifiableSet(Set.copyOf(taintedFunctions));
        correlatedFindings = correlatedFindings == null
                ? List.of() : Collections.unmodifiableList(List.copyOf(correlatedFindings));
    }
}
