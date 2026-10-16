package io.github.rezabakhshi.embedra.analyzers.crypto.dataflow;

import java.util.Objects;

/**
 * Directed call graph edge modeling parameter and taint transfer across functions.
 */
public record InterproceduralCallEdge(
        long callerAddress,
        String callerFunction,
        long callSiteAddress,
        long calleeAddress,
        String calleeFunction,
        int parameterIndex,
        String taintedArgument) {

    public InterproceduralCallEdge {
        Objects.requireNonNull(callerFunction, "callerFunction must not be null");
        Objects.requireNonNull(calleeFunction, "calleeFunction must not be null");
        Objects.requireNonNull(taintedArgument, "taintedArgument must not be null");
    }
}
