package io.github.rezabakhshi.embedra.analyzers.crypto.dataflow;

import java.util.Objects;

/**
 * Single step or transition in an interprocedural taint propagation path.
 */
public record TaintPropagationStep(
        long fromAddress,
        long toAddress,
        String fromSymbol,
        String toSymbol,
        String operation,
        String taintedVariableOrRegister) {

    public TaintPropagationStep {
        Objects.requireNonNull(fromSymbol, "fromSymbol must not be null");
        Objects.requireNonNull(toSymbol, "toSymbol must not be null");
        Objects.requireNonNull(operation, "operation must not be null");
        Objects.requireNonNull(taintedVariableOrRegister, "taintedVariableOrRegister must not be null");
    }
}
