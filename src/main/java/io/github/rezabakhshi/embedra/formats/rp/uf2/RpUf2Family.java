package io.github.rezabakhshi.embedra.formats.rp.uf2;

import java.util.Optional;

/**
 * Recognized UF2 family IDs for Raspberry Pi microcontrollers.
 */
public enum RpUf2Family {
    RP2040(0xe48bff56L, "RP2040", "ARMv6-M", "ARM Cortex-M0+"),
    RP2350_ARM_SECURE(0xe48bff57L, "RP2350", "ARMv8-M", "ARM Cortex-M33 Secure"),
    RP2350_RISCV(0xe48bff58L, "RP2350", "RV32IMAC", "Hazard3 RISC-V"),
    RP2350_ARM_NON_SECURE(0xe48bff59L, "RP2350", "ARMv8-M", "ARM Cortex-M33 Non-Secure");

    private final long familyId;

    private final String chip;

    private final String architecture;

    private final String description;

    RpUf2Family(long familyId, String chip, String architecture, String description) {
        this.familyId = familyId;
        this.chip = chip;
        this.architecture = architecture;
        this.description = description;
    }

    public long familyId() {
        return familyId;
    }

    public String chip() {
        return chip;
    }

    public String architecture() {
        return architecture;
    }

    public String description() {
        return description;
    }

    public static Optional<RpUf2Family> fromFamilyId(long id) {
        for (RpUf2Family family : values()) {
            if (family.familyId == id) {
                return Optional.of(family);
            }
        }
        return Optional.empty();
    }
}
