package io.github.rezabakhshi.embedra.targets.stm8.catalog;

import io.github.rezabakhshi.embedra.core.catalog.SupportState;
import java.util.List;
import java.util.Objects;

/**
 * Immutable record representing an exact orderable STMicroelectronics STM8 silicon part.
 */
public record Stm8PartRecord(
        String exactPart,
        String family,
        String subfamily,
        String packageType,
        long flashBytes,
        long ramBytes,
        long eepromBytes,
        long optionBytes,
        long bootRomBytes,
        List<String> peripherals,
        SupportState supportState,
        String datasheet) {

    public Stm8PartRecord {
        Objects.requireNonNull(exactPart, "exactPart must not be null");
        Objects.requireNonNull(family, "family must not be null");
        Objects.requireNonNull(subfamily, "subfamily must not be null");
        Objects.requireNonNull(packageType, "packageType must not be null");
        Objects.requireNonNull(supportState, "supportState must not be null");
        Objects.requireNonNull(datasheet, "datasheet must not be null");
        peripherals = peripherals == null ? List.of() : List.copyOf(peripherals);
        if (exactPart.isBlank()) {
            throw new IllegalArgumentException("exactPart must not be blank");
        }
        if (flashBytes <= 0 || ramBytes <= 0 || eepromBytes < 0 || optionBytes < 0 || bootRomBytes < 0) {
            throw new IllegalArgumentException("Memory sizes must be valid non-negative numbers");
        }
    }

    public long flashStart() {
        return 0x008000L;
    }

    public long flashEnd() {
        return flashStart() + flashBytes - 1L;
    }

    public long ramStart() {
        return 0x000000L;
    }

    public long ramEnd() {
        return ramStart() + ramBytes - 1L;
    }

    public long eepromStart() {
        return 0x004000L;
    }

    public long eepromEnd() {
        return eepromStart() + eepromBytes - 1L;
    }

    public long optionBytesStart() {
        return 0x004800L;
    }

    public long optionBytesEnd() {
        return optionBytesStart() + optionBytes - 1L;
    }

    public long peripheralsStart() {
        return 0x005000L;
    }

    public long peripheralsEnd() {
        return 0x0057FFL;
    }

    public long bootRomStart() {
        return 0x006000L;
    }

    public long bootRomEnd() {
        return 0x0067FFL;
    }
}
