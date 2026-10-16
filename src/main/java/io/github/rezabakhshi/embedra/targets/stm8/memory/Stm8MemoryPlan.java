package io.github.rezabakhshi.embedra.targets.stm8.memory;

import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.targets.stm8.catalog.Stm8PartRecord;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Validated memory layout plan for an STM8 microcontroller.
 */
public record Stm8MemoryPlan(
        Stm8PartRecord part,
        List<Stm8MemoryRegion> regions) {

    public Stm8MemoryPlan {
        Objects.requireNonNull(part, "part must not be null");
        regions = regions == null ? List.of() : List.copyOf(regions);
    }

    public Optional<Stm8MemoryRegion> findRegion(long address) {
        for (Stm8MemoryRegion region : regions) {
            if (region.contains(address)) {
                return Optional.of(region);
            }
        }
        return Optional.empty();
    }

    public Optional<Stm8MemoryRegion> findRegionByName(String name) {
        Objects.requireNonNull(name, "name must not be null");
        for (Stm8MemoryRegion region : regions) {
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
        return findRegion(address).map(Stm8MemoryRegion::executable).orElse(false);
    }

    public boolean isWritable(long address) {
        return findRegion(address).map(Stm8MemoryRegion::writable).orElse(false);
    }

    public void validate() throws DiagnosticException {
        for (int i = 0; i < regions.size(); i++) {
            Stm8MemoryRegion r1 = regions.get(i);
            for (int j = i + 1; j < regions.size(); j++) {
                Stm8MemoryRegion r2 = regions.get(j);
                if (r1.overlaps(r2)) {
                    throw new DiagnosticException(Diagnostic.error(
                        DiagnosticCode.STM8_MAPPING_CONFLICT,
                        String.format("Memory region conflict: %s (0x%06X-0x%06X) overlaps %s (0x%06X-0x%06X)",
                            r1.name(), r1.startAddress(), r1.endAddress(),
                            r2.name(), r2.startAddress(), r2.endAddress()),
                        null));
                }
            }
        }

        Stm8MemoryRegion flashRegion = findRegionByName("FLASH")
            .orElseThrow(() -> new DiagnosticException(Diagnostic.error(
                DiagnosticCode.STM8_MAPPING_FAILED, "Missing FLASH region in STM8 memory plan", null)));

        if (flashRegion.startAddress() != 0x008000L) {
            throw new DiagnosticException(Diagnostic.error(
                DiagnosticCode.STM8_MAPPING_FAILED,
                "STM8 Flash must begin at 0x008000, got: 0x" + Long.toHexString(flashRegion.startAddress()),
                null));
        }

        if (flashRegion.sizeBytes() != part.flashBytes()) {
            throw new DiagnosticException(Diagnostic.error(
                DiagnosticCode.STM8_MAPPING_FAILED,
                "Flash size mismatch: planned " + flashRegion.sizeBytes() + " vs part " + part.flashBytes(),
                null));
        }
    }
}
