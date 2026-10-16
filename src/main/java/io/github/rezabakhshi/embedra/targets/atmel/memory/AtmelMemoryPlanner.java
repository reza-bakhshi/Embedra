package io.github.rezabakhshi.embedra.targets.atmel.memory;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.targets.atmel.catalog.AtmelAddressModel;
import io.github.rezabakhshi.embedra.targets.atmel.catalog.AtmelPartRecord;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Pure memory layout planner for Atmel / Microchip AVR and SAM microcontrollers.
 */
public final class AtmelMemoryPlanner {

    private AtmelMemoryPlanner() {
    }

    public static AtmelMemoryPlan plan(
            AtmelPartRecord part, ParserLimits limits, CancellationToken token)
            throws DiagnosticException {
        Objects.requireNonNull(part, "part must not be null");
        Objects.requireNonNull(limits, "limits must not be null");
        Objects.requireNonNull(token, "token must not be null");

        token.throwIfCancellationRequested();

        long totalBytes = part.flashBytes() + part.ramBytes() + part.eepromBytes();
        if (totalBytes > limits.maxAllocationBytes()) {
            throw new DiagnosticException(Diagnostic.error(
                DiagnosticCode.LIMIT_EXCEEDED,
                "Requested Atmel memory plan exceeds maximum allocation limit: " + totalBytes,
                null));
        }

        List<AtmelMemoryRegion> regions = new ArrayList<>();

        if (part.addressModel() == AtmelAddressModel.LINEAR_32BIT) {
            planSamLinear(part, regions);
        } else if (part.addressModel() == AtmelAddressModel.HARVARD_UNIFIED_DATA_ALIAS) {
            planAvrDxUnified(part, regions);
        } else {
            planAvrClassicHarvard(part, regions);
        }

        // Validate that regions within each address space do not overlap
        validateNonOverlap(part, regions);

        return new AtmelMemoryPlan(part, regions);
    }

    private static void planAvrClassicHarvard(AtmelPartRecord part, List<AtmelMemoryRegion> regions) {
        // 1. Program Memory ('code' space)
        regions.add(new AtmelMemoryRegion(
            "CODE_FLASH",
            AtmelMemoryRegionKind.CODE_FLASH,
            "code",
            part.flashStart(),
            part.flashBytes(),
            true, false, true, false
        ));

        // 2. Data Memory ('data' space)
        // Standard I/O memory (0x0020 .. 0x005F)
        regions.add(new AtmelMemoryRegion(
            "IO_REGISTERS",
            AtmelMemoryRegionKind.IO_REGISTERS,
            "data",
            0x0020L,
            0x0040L,
            true, true, false, true
        ));

        // Extended I/O memory if SRAM starts above 0x0060 (e.g. at 0x0100 on ATmega328P)
        if (part.ramStart() > 0x0060L) {
            regions.add(new AtmelMemoryRegion(
                "EXTENDED_IO",
                AtmelMemoryRegionKind.IO_REGISTERS,
                "data",
                0x0060L,
                part.ramStart() - 0x0060L,
                true, true, false, true
            ));
        }

        // Internal SRAM
        regions.add(new AtmelMemoryRegion(
            "INTERNAL_SRAM",
            AtmelMemoryRegionKind.INTERNAL_SRAM,
            "data",
            part.ramStart(),
            part.ramBytes(),
            true, true, false, false
        ));

        // 3. EEPROM ('eeprom' space)
        if (part.hasEeprom()) {
            regions.add(new AtmelMemoryRegion(
                "DATA_EEPROM",
                AtmelMemoryRegionKind.DATA_EEPROM,
                "eeprom",
                part.eepromStart(),
                part.eepromBytes(),
                true, true, false, false
            ));
        }

        // 4. Dedicated I/O Direct Space ('io' space)
        regions.add(new AtmelMemoryRegion(
            "IO_DIRECT",
            AtmelMemoryRegionKind.IO_REGISTERS,
            "io",
            0x0000L,
            0x0040L,
            true, true, false, true
        ));

        // 5. Configuration Fuses
        regions.add(new AtmelMemoryRegion(
            "FUSES",
            AtmelMemoryRegionKind.FUSES,
            "code",
            0x00820000L,
            4L,
            true, false, false, false
        ));
    }

    private static void planAvrDxUnified(AtmelPartRecord part, List<AtmelMemoryRegion> regions) {
        // 1. Program Memory ('code' space)
        regions.add(new AtmelMemoryRegion(
            "CODE_FLASH",
            AtmelMemoryRegionKind.CODE_FLASH,
            "code",
            part.flashStart(),
            part.flashBytes(),
            true, false, true, false
        ));

        // 2. Data Memory ('data' space)
        // Peripherals MMIO (0x0000 .. 0x0FFF)
        regions.add(new AtmelMemoryRegion(
            "PERIPHERALS_MMIO",
            AtmelMemoryRegionKind.PERIPHERALS_MMIO,
            "data",
            0x0000L,
            0x1000L,
            true, true, false, true
        ));

        // Data EEPROM (0x1400 .. 0x15FF)
        if (part.hasEeprom()) {
            regions.add(new AtmelMemoryRegion(
                "DATA_EEPROM",
                AtmelMemoryRegionKind.DATA_EEPROM,
                "data",
                part.eepromStart(),
                part.eepromBytes(),
                true, true, false, false
            ));
        }

        // Internal SRAM (0x4000 .. ramEnd)
        regions.add(new AtmelMemoryRegion(
            "INTERNAL_SRAM",
            AtmelMemoryRegionKind.INTERNAL_SRAM,
            "data",
            part.ramStart(),
            part.ramBytes(),
            true, true, false, false
        ));

        // Flash Data Space Read-Only Alias (0x8000 .. 0xFFFF)
        if (part.hasFlashDataAlias()) {
            regions.add(new AtmelMemoryRegion(
                "FLASH_DATA_ALIAS",
                AtmelMemoryRegionKind.FLASH_DATA_ALIAS,
                "data",
                part.flashDataAliasStart(),
                part.flashDataAliasBytes(),
                true, false, false, false
            ));
        }
    }

    private static void planSamLinear(AtmelPartRecord part, List<AtmelMemoryRegion> regions) {
        // 1. Code Flash
        regions.add(new AtmelMemoryRegion(
            "CODE_FLASH",
            AtmelMemoryRegionKind.CODE_FLASH,
            "default",
            part.flashStart(),
            part.flashBytes(),
            true, false, true, false
        ));

        // 2. Internal SRAM
        regions.add(new AtmelMemoryRegion(
            "INTERNAL_SRAM",
            AtmelMemoryRegionKind.INTERNAL_SRAM,
            "default",
            part.ramStart(),
            part.ramBytes(),
            true, true, false, false
        ));

        // 3. Peripherals MMIO (0x40000000 .. 0x41FFFFFF)
        regions.add(new AtmelMemoryRegion(
            "PERIPHERALS_MMIO",
            AtmelMemoryRegionKind.PERIPHERALS_MMIO,
            "default",
            0x40000000L,
            0x02000000L,
            true, true, false, true
        ));

        // 4. SAM-BA Boot ROM if applicable
        if ("SAME".equalsIgnoreCase(part.series())) {
            long romBase = "SAME70Q21".equalsIgnoreCase(part.exactPart()) ? 0x00800000L : 0x00100000L;
            regions.add(new AtmelMemoryRegion(
                "SAM_BA_ROM",
                AtmelMemoryRegionKind.BOOT_ROM,
                "default",
                romBase,
                0x00010000L,
                true, false, true, false
            ));
        }
    }

    private static void validateNonOverlap(AtmelPartRecord part, List<AtmelMemoryRegion> regions)
            throws DiagnosticException {
        for (int i = 0; i < regions.size(); i++) {
            AtmelMemoryRegion r1 = regions.get(i);
            for (int j = i + 1; j < regions.size(); j++) {
                AtmelMemoryRegion r2 = regions.get(j);
                if (!r1.addressSpace().equalsIgnoreCase(r2.addressSpace())) {
                    continue; // Harvard spaces are physically disjoint
                }
                long maxStart = Math.max(r1.start(), r2.start());
                long minEnd = Math.min(r1.end(), r2.end());
                if (maxStart <= minEnd) {
                    throw new DiagnosticException(Diagnostic.error(
                        DiagnosticCode.ATMEL_MAPPING_CONFLICT,
                        String.format(
                            "Overlapping memory regions in %s space '%s': %s (0x%X..0x%X) and %s (0x%X..0x%X)",
                            part.exactPart(), r1.addressSpace(),
                            r1.name(), r1.start(), r1.end(),
                            r2.name(), r2.start(), r2.end()),
                        null));
                }
            }
        }
    }
}
