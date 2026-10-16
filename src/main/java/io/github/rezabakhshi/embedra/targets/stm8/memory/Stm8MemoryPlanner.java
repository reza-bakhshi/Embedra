package io.github.rezabakhshi.embedra.targets.stm8.memory;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.targets.stm8.catalog.Stm8PartRecord;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Pure memory layout planner for STM8 microcontrollers strictly isolated from STM32 Cortex-M contracts.
 */
public final class Stm8MemoryPlanner {

    private Stm8MemoryPlanner() {
    }

    public static Stm8MemoryPlan plan(
            Stm8PartRecord part, ParserLimits limits, CancellationToken token)
            throws DiagnosticException {
        Objects.requireNonNull(part, "part must not be null");
        Objects.requireNonNull(limits, "limits must not be null");
        Objects.requireNonNull(token, "token must not be null");

        token.throwIfCancellationRequested();

        long totalBytes = part.ramBytes() + part.eepromBytes() + part.optionBytes()
            + part.bootRomBytes() + 2048L + part.flashBytes();
        if (totalBytes > limits.maxAllocationBytes()) {
            throw new DiagnosticException(Diagnostic.error(
                DiagnosticCode.LIMIT_EXCEEDED,
                "Requested STM8 memory plan exceeds maximum allocation limit: " + totalBytes,
                null));
        }

        // Validate physical boundaries per RM0016 / RM0031
        if (part.ramEnd() >= 0x004000L) {
            throw new DiagnosticException(Diagnostic.error(
                DiagnosticCode.STM8_MAPPING_CONFLICT,
                "RAM range (0x000000-0x" + Long.toHexString(part.ramEnd())
                    + ") collides with EEPROM base 0x004000",
                null));
        }

        if (part.eepromBytes() > 0 && part.eepromEnd() >= 0x004800L) {
            throw new DiagnosticException(Diagnostic.error(
                DiagnosticCode.STM8_MAPPING_CONFLICT,
                "EEPROM range (0x004000-0x" + Long.toHexString(part.eepromEnd())
                    + ") collides with Option Bytes base 0x004800",
                null));
        }

        if (part.optionBytesEnd() >= 0x005000L) {
            throw new DiagnosticException(Diagnostic.error(
                DiagnosticCode.STM8_MAPPING_CONFLICT,
                "Option bytes range collides with Peripherals base 0x005000",
                null));
        }

        if (part.flashEnd() > 0xFFFFFFL) {
            throw new DiagnosticException(Diagnostic.error(
                DiagnosticCode.STM8_MAPPING_CONFLICT,
                "Flash range extends beyond 24-bit physical address space: 0x" + Long.toHexString(part.flashEnd()),
                null));
        }

        List<Stm8MemoryRegion> regions = new ArrayList<>();

        // 1. RAM at 0x000000
        regions.add(new Stm8MemoryRegion(
            "RAM",
            Stm8MemoryRegionKind.RAM,
            part.ramStart(),
            part.ramBytes(),
            true,
            true,
            false,
            false));

        // 2. Data EEPROM at 0x004000 (if present)
        if (part.eepromBytes() > 0) {
            regions.add(new Stm8MemoryRegion(
                "DATA_EEPROM",
                Stm8MemoryRegionKind.EEPROM,
                part.eepromStart(),
                part.eepromBytes(),
                true,
                true,
                false,
                false));
        }

        // 3. Option bytes at 0x004800
        if (part.optionBytes() > 0) {
            regions.add(new Stm8MemoryRegion(
                "OPTION_BYTES",
                Stm8MemoryRegionKind.OPTION_BYTES,
                part.optionBytesStart(),
                part.optionBytes(),
                true,
                true,
                false,
                true));
        }

        // 4. Peripheral registers at 0x005000 - 0x0057FF (2 KiB)
        regions.add(new Stm8MemoryRegion(
            "PERIPHERALS",
            Stm8MemoryRegionKind.PERIPHERALS,
            part.peripheralsStart(),
            part.peripheralsEnd() - part.peripheralsStart() + 1L,
            true,
            true,
            false,
            true));

        // 5. Boot ROM at 0x006000 - 0x0067FF (2 KiB)
        if (part.bootRomBytes() > 0) {
            regions.add(new Stm8MemoryRegion(
                "BOOT_ROM",
                Stm8MemoryRegionKind.BOOT_ROM,
                part.bootRomStart(),
                part.bootRomBytes(),
                true,
                false,
                true,
                false));
        }

        // 6. Program Flash at 0x008000
        regions.add(new Stm8MemoryRegion(
            "FLASH",
            Stm8MemoryRegionKind.FLASH,
            part.flashStart(),
            part.flashBytes(),
            true,
            false,
            true,
            false));

        Stm8MemoryPlan plan = new Stm8MemoryPlan(part, regions);
        plan.validate();
        return plan;
    }
}
