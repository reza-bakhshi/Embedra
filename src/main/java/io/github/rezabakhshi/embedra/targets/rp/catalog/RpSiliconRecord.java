package io.github.rezabakhshi.embedra.targets.rp.catalog;

import io.github.rezabakhshi.embedra.core.catalog.SupportState;
import java.util.List;
import java.util.Objects;

/**
 * An exact Raspberry Pi silicon part record (RP2040, RP2350A, RP2350B, RP2354A, RP2354B).
 */
public record RpSiliconRecord(
        String recordId,
        String exactPart,
        String series,
        String vendor,
        String packageName,
        String dimensions,
        int gpioCount,
        long internalFlashBytes,
        long externalXipLimitBytes,
        long sramBytes,
        List<RpSramBank> sramBanks,
        long bootRomBytes,
        long bootRomBase,
        long flashXipBase,
        int applicationCoreCount,
        List<String> bootArchitectures,
        String architectureSelectionMode,
        int pioBlocks,
        int pioStateMachinesPerBlock,
        boolean hasAtomicAliases,
        long atomicAliasBase,
        long sioBase,
        List<String> securityCapabilities,
        List<String> peripheralNames,
        SupportState supportState) {

    public RpSiliconRecord {
        Objects.requireNonNull(recordId, "recordId must not be null");
        Objects.requireNonNull(exactPart, "exactPart must not be null");
        Objects.requireNonNull(series, "series must not be null");
        Objects.requireNonNull(vendor, "vendor must not be null");
        Objects.requireNonNull(packageName, "packageName must not be null");
        Objects.requireNonNull(dimensions, "dimensions must not be null");
        Objects.requireNonNull(architectureSelectionMode, "architectureSelectionMode must not be null");
        Objects.requireNonNull(supportState, "supportState must not be null");

        if (gpioCount <= 0) {
            throw new IllegalArgumentException("gpioCount must be positive: " + gpioCount);
        }
        if (sramBytes <= 0) {
            throw new IllegalArgumentException("sramBytes must be positive: " + sramBytes);
        }
        if (applicationCoreCount <= 0) {
            throw new IllegalArgumentException("applicationCoreCount must be positive: " + applicationCoreCount);
        }
        if (pioBlocks <= 0) {
            throw new IllegalArgumentException("pioBlocks must be positive: " + pioBlocks);
        }
        if (pioStateMachinesPerBlock <= 0) {
            throw new IllegalArgumentException(
                    "pioStateMachinesPerBlock must be positive: " + pioStateMachinesPerBlock);
        }

        sramBanks = List.copyOf(sramBanks != null ? sramBanks : List.of());
        bootArchitectures = List.copyOf(bootArchitectures != null ? bootArchitectures : List.of());
        securityCapabilities = List.copyOf(securityCapabilities != null ? securityCapabilities : List.of());
        peripheralNames = List.copyOf(peripheralNames != null ? peripheralNames : List.of());

        if (bootArchitectures.isEmpty()) {
            throw new IllegalArgumentException("bootArchitectures must not be empty");
        }
    }

    /**
     * Checks if this silicon part includes stacked internal flash.
     */
    public boolean hasInternalFlash() {
        return internalFlashBytes > 0;
    }

    /**
     * Checks if this silicon part supports ARM Cortex-M architecture.
     */
    public boolean supportsArm() {
        return bootArchitectures.stream().anyMatch(a -> a.contains("ARM"));
    }

    /**
     * Checks if this silicon part supports RISC-V architecture.
     */
    public boolean supportsRiscV() {
        return bootArchitectures.stream().anyMatch(a -> a.contains("RISCV"));
    }

    /**
     * Total number of PIO state machines across all blocks.
     */
    public int totalPioStateMachines() {
        return pioBlocks * pioStateMachinesPerBlock;
    }
}
