package io.github.rezabakhshi.embedra.analyzers.crypto.signatures;

/**
 * Instruction set architecture target for compiler-aware cryptographic signatures (AN-011).
 */
public enum CryptoIsa {
    ARM_THUMB("ARM Thumb / Thumb-2"),
    XTENSA("Xtensa (ESP32 / S2 / S3)"),
    RISCV32("RISC-V 32-bit (ESP32-C3 / RP2350 Hazard3)"),
    GENERIC("Architecture-Independent / Byte Pattern");

    private final String displayName;

    CryptoIsa(String displayName) {
        this.displayName = displayName;
    }

    public String displayName() {
        return displayName;
    }
}
