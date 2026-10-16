package io.github.rezabakhshi.embedra.targets.atmel.vector;

import io.github.rezabakhshi.embedra.core.model.Confidence;
import java.util.Objects;

/**
 * Heuristic scoring and confidence evaluation for a candidate Atmel / Microchip interrupt vector table.
 */
public record AtmelVectorTableScore(
        int totalSlots,
        int validOpcodeCount,
        int validTargetCount,
        int uniqueTargetCount,
        boolean resetVectorValid,
        double opcodeRatio,
        double targetRatio,
        Confidence confidence,
        String reasoning) {

    public AtmelVectorTableScore {
        Objects.requireNonNull(confidence, "confidence must not be null");
        Objects.requireNonNull(reasoning, "reasoning must not be null");
    }

    public static AtmelVectorTableScore evaluate(
            int totalSlots,
            int validOpcodeCount,
            int validTargetCount,
            int uniqueTargetCount,
            boolean resetVectorValid) {
        double opcodeRatio = totalSlots > 0 ? (double) validOpcodeCount / totalSlots : 0.0;
        double targetRatio = totalSlots > 0 ? (double) validTargetCount / totalSlots : 0.0;

        if (!resetVectorValid) {
            return new AtmelVectorTableScore(
                totalSlots, validOpcodeCount, validTargetCount, uniqueTargetCount,
                false, opcodeRatio, targetRatio,
                Confidence.UNKNOWN,
                "Reset vector is invalid or missing"
            );
        }

        if (validTargetCount >= (totalSlots / 2) || validTargetCount >= 8) {
            return new AtmelVectorTableScore(
                totalSlots, validOpcodeCount, validTargetCount, uniqueTargetCount,
                true, opcodeRatio, targetRatio,
                Confidence.DERIVED,
                String.format("High confidence: %d/%d valid vectors with valid opcodes and targets",
                    validTargetCount, totalSlots)
            );
        }

        if (validTargetCount >= 2) {
            return new AtmelVectorTableScore(
                totalSlots, validOpcodeCount, validTargetCount, uniqueTargetCount,
                true, opcodeRatio, targetRatio,
                Confidence.HEURISTIC,
                String.format("Medium confidence: %d/%d valid vectors", validTargetCount, totalSlots)
            );
        }

        return new AtmelVectorTableScore(
            totalSlots, validOpcodeCount, validTargetCount, uniqueTargetCount,
            true, opcodeRatio, targetRatio,
            Confidence.HEURISTIC,
            "Low confidence: reset vector valid but few other active vectors"
        );
    }
}
