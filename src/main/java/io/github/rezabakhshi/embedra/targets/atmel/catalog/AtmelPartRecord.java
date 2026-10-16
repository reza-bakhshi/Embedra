package io.github.rezabakhshi.embedra.targets.atmel.catalog;

import io.github.rezabakhshi.embedra.core.catalog.SupportState;
import java.util.Objects;

/**
 * Immutable record representing an exact orderable Atmel / Microchip silicon part.
 */
public record AtmelPartRecord(
        String exactPart,
        String family,
        String series,
        String core,
        String arch,
        String ghidraLanguage,
        AtmelAddressModel addressModel,
        String packageCode,
        String datasheet,
        long flashStart,
        long flashBytes,
        long ramStart,
        long ramBytes,
        long eepromStart,
        long eepromBytes,
        long flashDataAliasStart,
        long flashDataAliasBytes,
        int vectorCount,
        int vectorStrideBytes,
        String vectorInstruction,
        SupportState supportState) {

    public AtmelPartRecord {
        Objects.requireNonNull(exactPart, "exactPart must not be null");
        Objects.requireNonNull(family, "family must not be null");
        Objects.requireNonNull(series, "series must not be null");
        Objects.requireNonNull(core, "core must not be null");
        Objects.requireNonNull(arch, "arch must not be null");
        Objects.requireNonNull(ghidraLanguage, "ghidraLanguage must not be null");
        Objects.requireNonNull(addressModel, "addressModel must not be null");
        Objects.requireNonNull(packageCode, "packageCode must not be null");
        Objects.requireNonNull(datasheet, "datasheet must not be null");
        Objects.requireNonNull(vectorInstruction, "vectorInstruction must not be null");
        Objects.requireNonNull(supportState, "supportState must not be null");

        if (exactPart.isBlank()) {
            throw new IllegalArgumentException("exactPart must not be blank");
        }
        if (flashBytes <= 0 || ramBytes <= 0) {
            throw new IllegalArgumentException("Flash and RAM bytes must be positive");
        }
        if (vectorCount <= 0 || (vectorStrideBytes != 2 && vectorStrideBytes != 4)) {
            throw new IllegalArgumentException("Vector count must be positive and stride must be 2 or 4");
        }
    }

    public long flashEnd() {
        return flashStart + flashBytes - 1L;
    }

    public long ramEnd() {
        return ramStart + ramBytes - 1L;
    }

    public long eepromEnd() {
        return eepromBytes > 0 ? eepromStart + eepromBytes - 1L : eepromStart;
    }

    public boolean isAvr() {
        return "AVR".equalsIgnoreCase(family);
    }

    public boolean isSam() {
        return "SAM".equalsIgnoreCase(family);
    }

    public boolean hasEeprom() {
        return eepromBytes > 0;
    }

    public boolean hasFlashDataAlias() {
        return flashDataAliasBytes > 0;
    }

    public static AtmelPartRecord defaultAtmega328p() {
        return new AtmelPartRecord(
            "ATmega328P", "AVR", "ATmega", "AVR RISC", "AVR8", "avr8:LE:16:default",
            AtmelAddressModel.HARVARD_SEPARATE, "TQFP32 / DIP28", "Microchip DS40002061B",
            0x00000000L, 32768L, 0x00000100L, 2048L, 0x00000000L, 1024L,
            0L, 0L, 26, 4, "JMP", SupportState.PLANNED
        );
    }

    public static AtmelPartRecord defaultAtmega2560() {
        return new AtmelPartRecord(
            "ATmega2560", "AVR", "ATmega", "AVR RISC", "AVR8", "avr8:LE:24:default",
            AtmelAddressModel.HARVARD_SEPARATE, "TQFP100", "Microchip DS40002211A",
            0x00000000L, 262144L, 0x00000200L, 8192L, 0x00000000L, 4096L,
            0L, 0L, 57, 4, "JMP", SupportState.PLANNED
        );
    }

    public static AtmelPartRecord defaultAttiny85() {
        return new AtmelPartRecord(
            "ATtiny85", "AVR", "ATtiny", "AVR RISC", "AVR8", "avr8:LE:16:default",
            AtmelAddressModel.HARVARD_SEPARATE, "SOIC8 / DIP8", "Microchip DS40001509B",
            0x00000000L, 8192L, 0x00000060L, 512L, 0x00000000L, 512L,
            0L, 0L, 15, 2, "RJMP", SupportState.PLANNED
        );
    }

    public static AtmelPartRecord defaultAvr128da48() {
        return new AtmelPartRecord(
            "AVR128DA48", "AVR", "AVR-Dx", "AVRxt", "AVR8X", "avr8:LE:24:xmega",
            AtmelAddressModel.HARVARD_UNIFIED_DATA_ALIAS, "TQFP48", "Microchip DS40002183B",
            0x00000000L, 131072L, 0x00004000L, 16384L, 0x00001400L, 512L,
            0x00008000L, 32768L, 42, 4, "JMP", SupportState.PLANNED
        );
    }

    public static AtmelPartRecord defaultSamd21g18a() {
        return new AtmelPartRecord(
            "SAMD21G18A", "SAM", "SAMD", "ARM Cortex-M0+", "ARMv6-M", "ARM:LE:32:v6M",
            AtmelAddressModel.LINEAR_32BIT, "TQFP48", "Microchip DS40001882G",
            0x00000000L, 262144L, 0x20000000L, 32768L, 0L, 0L,
            0L, 0L, 44, 4, "THUMB_VECTOR", SupportState.PLANNED
        );
    }

    public static AtmelPartRecord defaultSame70q21() {
        return new AtmelPartRecord(
            "SAME70Q21", "SAM", "SAME", "ARM Cortex-M7", "ARMv7E-M", "ARM:LE:32:v7EM",
            AtmelAddressModel.LINEAR_32BIT, "LQFP144", "Microchip DS60001527E",
            0x00400000L, 2097152L, 0x20400000L, 393216L, 0L, 0L,
            0L, 0L, 85, 4, "THUMB_VECTOR", SupportState.PLANNED
        );
    }
}
