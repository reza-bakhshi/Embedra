package io.github.rezabakhshi.embedra.targets.nordic.memory;

import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.targets.nordic.catalog.NordicPartRecord;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Validated memory layout plan for a Nordic Semiconductor SoC or microcontroller.
 */
public record NordicMemoryPlan(
        NordicPartRecord part,
        List<NordicMemoryRegion> regions) {

    public NordicMemoryPlan {
        Objects.requireNonNull(part, "part must not be null");
        regions = regions == null ? List.of() : List.copyOf(regions);
    }

    public Optional<NordicMemoryRegion> findRegion(long address) {
        for (NordicMemoryRegion region : regions) {
            if (region.contains(address)) {
                return Optional.of(region);
            }
        }
        return Optional.empty();
    }

    public Optional<NordicMemoryRegion> findRegionByName(String name) {
        Objects.requireNonNull(name, "name must not be null");
        for (NordicMemoryRegion region : regions) {
            if (region.name().equalsIgnoreCase(name)) {
                return Optional.of(region);
            }
        }
        return Optional.empty();
    }

    public boolean isMapped(long address) {
        return findRegion(address).isPresent();
    }

    public boolean isExecutable(long address) {
        return findRegion(address).map(NordicMemoryRegion::executable).orElse(false);
    }

    public boolean isWritable(long address) {
        return findRegion(address).map(NordicMemoryRegion::writable).orElse(false);
    }

    public void validate() throws DiagnosticException {
        for (int i = 0; i < regions.size(); i++) {
            NordicMemoryRegion r1 = regions.get(i);
            for (int j = i + 1; j < regions.size(); j++) {
                NordicMemoryRegion r2 = regions.get(j);
                if (r1.overlaps(r2)) {
                    throw new DiagnosticException(Diagnostic.error(
                        DiagnosticCode.NORDIC_MAPPING_CONFLICT,
                        String.format("Memory region conflict: %s (0x%08X-0x%08X) overlaps %s (0x%08X-0x%08X)",
                            r1.name(), r1.startAddress(), r1.endAddress(),
                            r2.name(), r2.startAddress(), r2.endAddress()),
                        null));
                }
            }
        }

        NordicMemoryRegion flashRegion = findRegionByName("CODE_FLASH")
            .orElseThrow(() -> new DiagnosticException(Diagnostic.error(
                DiagnosticCode.NORDIC_MAPPING_FAILED, "Missing CODE_FLASH region in Nordic memory plan", null)));

        if (flashRegion.startAddress() != 0x00000000L) {
            throw new DiagnosticException(Diagnostic.error(
                DiagnosticCode.NORDIC_MAPPING_FAILED,
                "Nordic Code Flash must begin at 0x00000000, got: 0x" + Long.toHexString(flashRegion.startAddress()),
                null));
        }

        NordicMemoryRegion ramRegion = findRegionByName("SRAM")
            .orElseThrow(() -> new DiagnosticException(Diagnostic.error(
                DiagnosticCode.NORDIC_MAPPING_FAILED, "Missing SRAM region in Nordic memory plan", null)));

        if (ramRegion.startAddress() != 0x20000000L) {
            throw new DiagnosticException(Diagnostic.error(
                DiagnosticCode.NORDIC_MAPPING_FAILED,
                "Nordic SRAM must begin at 0x20000000, got: 0x" + Long.toHexString(ramRegion.startAddress()),
                null));
        }
    }
}
