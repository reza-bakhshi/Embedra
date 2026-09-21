package io.github.rezabakhshi.embedra.core.model;

/** Distinguishes instruction-bearing processors from non-disassemblable hardware. */
public enum ProcessorKind {
    CPU_CORE(true),
    PROGRAMMABLE_COPROCESSOR(true),
    RADIO_PROCESSOR(true),
    BOOT_ROM(true),
    DMA_BUS_MASTER(false),
    FIXED_FUNCTION_ACCELERATOR(false),
    RADIO_HARDWARE(false);

    private final boolean executesRecoverableInstructions;

    ProcessorKind(boolean executesRecoverableInstructions) {
        this.executesRecoverableInstructions = executesRecoverableInstructions;
    }

    public boolean executesRecoverableInstructions() {
        return executesRecoverableInstructions;
    }
}
