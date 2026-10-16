package io.github.rezabakhshi.embedra.targets.stm8.vector;

import io.github.rezabakhshi.embedra.core.model.Confidence;
import java.util.Objects;

/**
 * Heuristic scoring and confidence evaluation for a candidate STM8 interrupt vector table.
 */
public record Stm8VectorTableScore(
        int totalSlots,
        int validOpcodeCount,
        int validTargetCount,
        int uniqueTargetCount,
        boolean resetVectorValid,
        double opcodeRatio,
        double targetRatio,
        Confidence confidence,
        String reasoning) {

    public Stm8VectorTableScore {
        Objects.requireNonNull(confidence, "confidence must not be null");
        Objects.requireNonNull(reasoning, "reasoning must not be null");
    }

    public static Stm8VectorTableScore evaluate(
            int validOpcodeCount,
            int validTargetCount,
            int uniqueTargetCount,
            boolean resetVectorValid) {
        int totalSlots = 32;
        double opcodeRatio = (double) validOpcodeCount / totalSlots;
        double targetRatio = (double) validTargetCount / totalSlots;

        if (!resetVectorValid) {
            return new Stm8VectorTableScore(
                totalSlots,
                validOpcodeCount,
                validTargetCount,
                uniqueTargetCount,
                false,
                opcodeRatio,
                targetRatio,
                Confidence.UNKNOWN,
                "Reset vector (slot 0) is invalid or not an extended jump opcode 0x82"
            );
        }

        if (validOpcodeCount >= 16 && validTargetCount >= 16) {
            return new Stm8VectorTableScore(
                totalSlots,
                validOpcodeCount,
                validTargetCount,
                uniqueTargetCount,
                true,
                opcodeRatio,
                targetRatio,
                Confidence.DERIVED,
                String.format("High confidence: %d/32 valid vectors with 0x82 JPF opcode and valid targets",
                    validTargetCount)
            );
        }

        if (validOpcodeCount >= 8 && validTargetCount >= 8) {
            return new Stm8VectorTableScore(
                totalSlots,
                validOpcodeCount,
                validTargetCount,
                uniqueTargetCount,
                true,
                opcodeRatio,
                targetRatio,
                Confidence.DERIVED,
                String.format("High confidence: %d/32 valid vectors including reset vector", validTargetCount)
            );
        }

        if (validOpcodeCount >= 4 && validTargetCount >= 4) {
            return new Stm8VectorTableScore(
                totalSlots,
                validOpcodeCount,
                validTargetCount,
                uniqueTargetCount,
                true,
                opcodeRatio,
                targetRatio,
                Confidence.HEURISTIC,
                String.format("Medium confidence: %d/32 vectors valid", validTargetCount)
            );
        }

        if (validTargetCount >= 1) {
            return new Stm8VectorTableScore(
                totalSlots,
                validOpcodeCount,
                validTargetCount,
                uniqueTargetCount,
                true,
                opcodeRatio,
                targetRatio,
                Confidence.HEURISTIC,
                String.format("Low confidence: only %d/32 vectors valid", validTargetCount)
            );
        }

        return new Stm8VectorTableScore(
            totalSlots,
            validOpcodeCount,
            validTargetCount,
            uniqueTargetCount,
            false,
            opcodeRatio,
            targetRatio,
            Confidence.UNKNOWN,
            "No valid vector entries identified"
        );
    }
}
