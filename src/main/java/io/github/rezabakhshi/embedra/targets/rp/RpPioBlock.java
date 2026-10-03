package io.github.rezabakhshi.embedra.targets.rp;

import java.util.List;
import java.util.Objects;

/**
 * Immutable model of a Programmable I/O (PIO) block on RP2040 (2 blocks) and RP2350 (3 blocks).
 */
public record RpPioBlock(
        int blockIndex,
        long baseAddress,
        int stateMachineCount,
        int instructionMemoryWords,
        int fifoDepth,
        List<String> irqNames) {

    public static final long PIO0_BASE = 0x50200000L;

    public static final long PIO1_BASE = 0x50300000L;

    public static final long PIO2_BASE = 0x50400000L;

    public static final int SM_COUNT = 4;

    public static final int INSTRUCTION_MEMORY_WORDS = 32;

    public static final int FIFO_DEPTH = 4;


    public RpPioBlock {
        if (blockIndex < 0 || blockIndex > 2) {
            throw new IllegalArgumentException("PIO block index must be 0, 1, or 2: " + blockIndex);
        }
        if (baseAddress <= 0) {
            throw new IllegalArgumentException("PIO base address must be positive: " + baseAddress);
        }
        if (stateMachineCount <= 0) {
            throw new IllegalArgumentException("State machine count must be positive: " + stateMachineCount);
        }
        if (instructionMemoryWords <= 0) {
            throw new IllegalArgumentException("Instruction memory words must be positive: " + instructionMemoryWords);
        }
        irqNames = List.copyOf(Objects.requireNonNull(irqNames, "irqNames must not be null"));
    }

    public static RpPioBlock pio0() {
        return new RpPioBlock(
                0, PIO0_BASE, SM_COUNT, INSTRUCTION_MEMORY_WORDS, FIFO_DEPTH,
                List.of("PIO0_IRQ_0", "PIO0_IRQ_1"));
    }

    public static RpPioBlock pio1() {
        return new RpPioBlock(
                1, PIO1_BASE, SM_COUNT, INSTRUCTION_MEMORY_WORDS, FIFO_DEPTH,
                List.of("PIO1_IRQ_0", "PIO1_IRQ_1"));
    }

    public static RpPioBlock pio2() {
        return new RpPioBlock(
                2, PIO2_BASE, SM_COUNT, INSTRUCTION_MEMORY_WORDS, FIFO_DEPTH,
                List.of("PIO2_IRQ_0", "PIO2_IRQ_1"));
    }

    public String blockName() {
        return "PIO" + blockIndex;
    }

    public boolean containsAddress(long address) {
        return address >= baseAddress && address < baseAddress + 0x1000L;
    }
}
