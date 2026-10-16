package io.github.rezabakhshi.embedra.targets.atmel;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.targets.atmel.catalog.AtmelPartRecord;
import io.github.rezabakhshi.embedra.targets.atmel.memory.AtmelMemoryPlan;
import io.github.rezabakhshi.embedra.targets.atmel.memory.AtmelMemoryPlanner;
import io.github.rezabakhshi.embedra.targets.atmel.memory.AtmelMemoryRegion;
import io.github.rezabakhshi.embedra.targets.atmel.memory.AtmelMemoryRegionKind;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Automated tests for AtmelMemoryPlanner.
 */
class AtmelMemoryPlannerTest {

    @Test
    void planClassicMegaAvrHarvardSpaces() throws DiagnosticException {
        AtmelPartRecord part = AtmelPartRecord.defaultAtmega328p();
        AtmelMemoryPlan plan = AtmelMemoryPlanner.plan(part, ParserLimits.defaults(), CancellationToken.none());

        assertNotNull(plan);
        assertEquals(part, plan.part());

        // 1. Code space
        List<AtmelMemoryRegion> codeRegions = plan.regionsForSpace("code");
        assertTrue(codeRegions.stream().anyMatch(r -> r.kind() == AtmelMemoryRegionKind.CODE_FLASH
            && r.start() == 0x0000L && r.length() == 32768L && r.execute()));

        // 2. Data space
        List<AtmelMemoryRegion> dataRegions = plan.regionsForSpace("data");
        assertTrue(dataRegions.stream().anyMatch(r -> r.kind() == AtmelMemoryRegionKind.INTERNAL_SRAM
            && r.start() == 0x0100L && r.length() == 2048L && r.write() && !r.execute()));
        assertTrue(dataRegions.stream().anyMatch(r -> r.kind() == AtmelMemoryRegionKind.IO_REGISTERS
            && r.start() == 0x0020L && r.length() == 64L));

        // 3. I/O space
        List<AtmelMemoryRegion> ioRegions = plan.regionsForSpace("io");
        assertTrue(ioRegions.stream().anyMatch(r -> r.start() == 0x0000L && r.length() == 64L && r.isVolatile()));

        // 4. EEPROM space
        List<AtmelMemoryRegion> eepromRegions = plan.regionsForSpace("eeprom");
        assertTrue(eepromRegions.stream().anyMatch(r -> r.start() == 0x0000L && r.length() == 1024L));

        // Mapped checks
        assertTrue(plan.isMapped("code", 0x0000L));
        assertTrue(plan.isMapped("code", 0x7FFFL));
        assertFalse(plan.isMapped("code", 0x8000L));
        assertTrue(plan.isExecutable("code", 0x0000L));

        assertTrue(plan.isMapped("data", 0x0100L));
        assertFalse(plan.isExecutable("data", 0x0100L));
    }

    @Test
    void planAvrDxUnifiedMemoryAliasing() throws DiagnosticException {
        AtmelPartRecord part = AtmelPartRecord.defaultAvr128da48();
        AtmelMemoryPlan plan = AtmelMemoryPlanner.plan(part, ParserLimits.defaults(), CancellationToken.none());

        assertNotNull(plan);

        // Code space: 128 KiB Flash
        assertTrue(plan.isMapped("code", 0x000000L));
        assertTrue(plan.isMapped("code", 0x01FFFFL));
        assertFalse(plan.isMapped("code", 0x020000L));

        // Data space: SRAM at 0x4000, Flash Data Alias at 0x8000
        List<AtmelMemoryRegion> dataRegions = plan.regionsForSpace("data");
        assertTrue(dataRegions.stream().anyMatch(r -> r.kind() == AtmelMemoryRegionKind.INTERNAL_SRAM
            && r.start() == 0x4000L && r.length() == 16384L));
        assertTrue(dataRegions.stream().anyMatch(r -> r.kind() == AtmelMemoryRegionKind.FLASH_DATA_ALIAS
            && r.start() == 0x8000L && r.length() == 32768L && r.read() && !r.write()));
    }

    @Test
    void planSamLinear32BitMemory() throws DiagnosticException {
        // SAMD21
        AtmelPartRecord samd = AtmelPartRecord.defaultSamd21g18a();
        AtmelMemoryPlan samdPlan = AtmelMemoryPlanner.plan(samd, ParserLimits.defaults(), CancellationToken.none());

        assertTrue(samdPlan.isMapped("default", 0x00000000L)); // Flash
        assertTrue(samdPlan.isExecutable("default", 0x00000000L));
        assertTrue(samdPlan.isMapped("default", 0x20000000L)); // SRAM
        assertFalse(samdPlan.isExecutable("default", 0x20000000L));
        assertTrue(samdPlan.isMapped("default", 0x40000000L)); // Peripherals MMIO

        // SAME70 with SAM-BA ROM
        AtmelPartRecord same = AtmelPartRecord.defaultSame70q21();
        AtmelMemoryPlan samePlan = AtmelMemoryPlanner.plan(same, ParserLimits.defaults(), CancellationToken.none());

        assertTrue(samePlan.isMapped("default", 0x00400000L)); // Flash
        assertTrue(samePlan.isMapped("default", 0x20400000L)); // SRAM
        assertTrue(samePlan.isMapped("default", 0x00800000L)); // SAM-BA ROM
        assertTrue(samePlan.isExecutable("default", 0x00800000L));
    }

    @Test
    void cancellationThrowsDiagnosticException() {
        AtmelPartRecord part = AtmelPartRecord.defaultAtmega328p();
        CancellationToken token = () -> true;
        assertThrows(DiagnosticException.class, () ->
            AtmelMemoryPlanner.plan(part, ParserLimits.defaults(), token)
        );
    }
}
