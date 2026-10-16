package io.github.rezabakhshi.embedra.targets.nordic.catalog;

import io.github.rezabakhshi.embedra.core.catalog.SupportState;
import java.util.Objects;

/**
 * Immutable record representing an exact orderable Nordic Semiconductor silicon part.
 */
public record NordicPartRecord(
        String exactPart,
        String series,
        String subfamily,
        String packageCode,
        String core,
        boolean fpu,
        long flashBytes,
        long ramBytes,
        long ficrStart,
        long ficrBytes,
        long uicrStart,
        long uicrBytes,
        long peripheralsStart,
        long peripheralsBytes,
        String cryptoCellName,
        long cryptoCellBase,
        long cryptoCellSize,
        boolean trustZone,
        boolean dualCore,
        SupportState supportState,
        String datasheet) {

    public NordicPartRecord {
        Objects.requireNonNull(exactPart, "exactPart must not be null");
        Objects.requireNonNull(series, "series must not be null");
        Objects.requireNonNull(subfamily, "subfamily must not be null");
        Objects.requireNonNull(packageCode, "packageCode must not be null");
        Objects.requireNonNull(core, "core must not be null");
        Objects.requireNonNull(supportState, "supportState must not be null");
        Objects.requireNonNull(datasheet, "datasheet must not be null");

        if (exactPart.isBlank()) {
            throw new IllegalArgumentException("exactPart must not be blank");
        }
        if (flashBytes <= 0 || ramBytes <= 0 || ficrBytes <= 0 || uicrBytes <= 0 || peripheralsBytes <= 0) {
            throw new IllegalArgumentException("Memory region sizes must be positive");
        }
    }

    public long flashStart() {
        return 0x00000000L;
    }

    public long flashEnd() {
        return flashStart() + flashBytes - 1L;
    }

    public long ramStart() {
        return 0x20000000L;
    }

    public long ramEnd() {
        return ramStart() + ramBytes - 1L;
    }

    public long ficrEnd() {
        return ficrStart + ficrBytes - 1L;
    }

    public long uicrEnd() {
        return uicrStart + uicrBytes - 1L;
    }

    public long peripheralsEnd() {
        return peripheralsStart + peripheralsBytes - 1L;
    }

    public boolean hasCryptoCell() {
        return cryptoCellBase > 0 && cryptoCellSize > 0;
    }

    public static NordicPartRecord defaultNrf51822() {
        return new NordicPartRecord(
            "nRF51822-QFAA", "nRF51", "nRF51822", "QFN48", "ARM Cortex-M0", false,
            262144L, 16384L, 0x10000000L, 0x100L, 0x10001000L, 0x100L, 0x40000000L, 0x00020000L,
            null, 0L, 0L, false, false, SupportState.PLANNED, "nRF51822 Product Specification"
        );
    }

    public static NordicPartRecord defaultNrf52832() {
        return new NordicPartRecord(
            "nRF52832-QFAA", "nRF52", "nRF52832", "QFN48", "ARM Cortex-M4F", true,
            524288L, 65536L, 0x10000000L, 0x100L, 0x10001000L, 0x100L, 0x40000000L, 0x00020000L,
            null, 0L, 0L, false, false, SupportState.PLANNED, "nRF52832 Product Specification"
        );
    }

    public static NordicPartRecord defaultNrf52840() {
        return new NordicPartRecord(
            "nRF52840-QIAA", "nRF52", "nRF52840", "aQFN73", "ARM Cortex-M4F", true,
            1048576L, 262144L, 0x10000000L, 0x100L, 0x10001000L, 0x100L, 0x40000000L, 0x00020000L,
            "CRYPTOCELL_310", 0x5002A000L, 0x1000L, false, false, SupportState.PLANNED,
            "nRF52840 Product Specification"
        );
    }

    public static NordicPartRecord defaultNrf5340() {
        return new NordicPartRecord(
            "nRF5340-QKAA", "nRF53", "nRF5340", "aQFN94", "ARM Cortex-M33", true,
            1048576L, 524288L, 0x10000000L, 0x1000L, 0x10001000L, 0x1000L, 0x40000000L, 0x00020000L,
            "CRYPTOCELL_312", 0x50840000L, 0x1000L, true, true, SupportState.PLANNED, "nRF5340 Product Specification"
        );
    }

    public static NordicPartRecord defaultNrf9160() {
        return new NordicPartRecord(
            "nRF9160-SICA", "nRF91", "nRF9160", "LGA", "ARM Cortex-M33", true,
            1048576L, 262144L, 0x10000000L, 0x1000L, 0x10001000L, 0x1000L, 0x40000000L, 0x00020000L,
            "CRYPTOCELL_312", 0x50840000L, 0x1000L, true, false, SupportState.PLANNED, "nRF9160 Product Specification"
        );
    }
}
