package io.github.rezabakhshi.embedra.analyzers.atmel;

import io.github.rezabakhshi.embedra.analyzers.strings.stack.StackInstruction;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Context containing memory bytes, functions, and symbols for Atmel/Microchip CTF/string/lead enrichment.
 */
public record AtmelCtfEnrichmentContext(
        AtmelSignatureContext signatureContext,
        byte[] flashBytes,
        long flashBase,
        Map<Long, String> symbolMap,
        Map<Long, List<StackInstruction>> functionInstructions) {

    public AtmelCtfEnrichmentContext {
        Objects.requireNonNull(signatureContext, "signatureContext must not be null");
        flashBytes = Objects.requireNonNull(flashBytes, "flashBytes must not be null").clone();
        if (flashBase < 0) {
            throw new IllegalArgumentException("flashBase must be non-negative");
        }
        symbolMap = Map.copyOf(symbolMap);
        functionInstructions = Map.copyOf(functionInstructions);
    }

    @Override
    public byte[] flashBytes() {
        return flashBytes.clone();
    }
}
