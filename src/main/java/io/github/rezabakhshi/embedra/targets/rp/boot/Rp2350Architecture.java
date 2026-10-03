package io.github.rezabakhshi.embedra.targets.rp.boot;

/**
 * CPU execution architecture for RP2350 / RP2354 firmware images.
 */
public enum Rp2350Architecture {
    ARM("ARM Cortex-M33", "ARMv8-M"),
    RISCV("Hazard3 RISC-V", "RV32IMAC");

    private final String description;

    private final String isa;

    Rp2350Architecture(String description, String isa) {
        this.description = description;
        this.isa = isa;
    }

    public String description() {
        return description;
    }

    public String isa() {
        return isa;
    }
}
