package io.github.rezabakhshi.embedra.targets.nordic.memory;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.targets.nordic.catalog.NordicPartRecord;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Pure memory layout planner for Nordic Semiconductor SoCs and microcontrollers.
 */
public final class NordicMemoryPlanner {

    private NordicMemoryPlanner() {
    }

    public static NordicMemoryPlan plan(
            NordicPartRecord part, ParserLimits limits, CancellationToken token)
            throws DiagnosticException {
        Objects.requireNonNull(part, "part must not be null");
        Objects.requireNonNull(limits, "limits must not be null");
        Objects.requireNonNull(token, "token must not be null");

        token.throwIfCancellationRequested();

        long totalBytes = part.flashBytes() + part.ramBytes() + part.ficrBytes()
            + part.uicrBytes() + part.peripheralsBytes();
        if (totalBytes > limits.maxAllocationBytes()) {
            throw new DiagnosticException(Diagnostic.error(
                DiagnosticCode.LIMIT_EXCEEDED,
                "Requested Nordic memory plan exceeds maximum allocation limit: " + totalBytes,
                null));
        }

        // Validate physical boundaries
        if (part.flashEnd() >= 0x20000000L) {
            throw new DiagnosticException(Diagnostic.error(
                DiagnosticCode.NORDIC_MAPPING_CONFLICT,
                "Flash range (0x00000000-0x" + Long.toHexString(part.flashEnd())
                    + ") collides with SRAM base 0x20000000",
                null));
        }

        List<NordicMemoryRegion> regions = new ArrayList<>();

        // 1. Primary Code Flash at 0x00000000
        regions.add(new NordicMemoryRegion(
            "CODE_FLASH",
            NordicMemoryRegionKind.CODE_FLASH,
            part.flashStart(),
            part.flashBytes(),
            true,
            false,
            true,
            part.trustZone()));

        // 2. Primary SRAM at 0x20000000
        regions.add(new NordicMemoryRegion(
            "SRAM",
            NordicMemoryRegionKind.SRAM,
            part.ramStart(),
            part.ramBytes(),
            true,
            true,
            true,
            part.trustZone()));

        // 3. FICR
        regions.add(new NordicMemoryRegion(
            "FICR",
            NordicMemoryRegionKind.FICR,
            part.ficrStart(),
            part.ficrBytes(),
            true,
            false,
            false,
            part.trustZone()));

        // 4. UICR
        regions.add(new NordicMemoryRegion(
            "UICR",
            NordicMemoryRegionKind.UICR,
            part.uicrStart(),
            part.uicrBytes(),
            true,
            true,
            false,
            part.trustZone()));

        // 5. Peripherals (APB/AHB and Secure)
        if (part.peripheralsStart() >= 0x50000000L) {
            regions.add(new NordicMemoryRegion(
                "PERIPHERALS_SECURE",
                NordicMemoryRegionKind.PERIPHERALS_SECURE,
                part.peripheralsStart(),
                part.peripheralsBytes(),
                true,
                true,
                false,
                true));

            regions.add(new NordicMemoryRegion(
                "PERIPHERALS_APB",
                NordicMemoryRegionKind.PERIPHERALS_APB,
                0x40000000L,
                part.peripheralsBytes(),
                true,
                true,
                false,
                false));
        } else {
            regions.add(new NordicMemoryRegion(
                "PERIPHERALS_APB",
                NordicMemoryRegionKind.PERIPHERALS_APB,
                part.peripheralsStart(),
                part.peripheralsBytes(),
                true,
                true,
                false,
                false));

            if (part.trustZone()) {
                regions.add(new NordicMemoryRegion(
                    "PERIPHERALS_SECURE",
                    NordicMemoryRegionKind.PERIPHERALS_SECURE,
                    0x50000000L,
                    0x00020000L,
                    true,
                    true,
                    false,
                    true));
            }
        }

        // 7. CryptoCell hardware peripheral (if present)
        if (part.hasCryptoCell()) {
            regions.add(new NordicMemoryRegion(
                part.cryptoCellName() != null ? part.cryptoCellName() : "CRYPTOCELL",
                NordicMemoryRegionKind.CRYPTOCELL,
                part.cryptoCellBase(),
                part.cryptoCellSize(),
                true,
                true,
                false,
                true));
        }

        // 8. Series-specific regions
        if (part.dualCore() && part.series().equalsIgnoreCase("nRF53")) {
            // nRF5340 Network Core physical spaces in global address map
            regions.add(new NordicMemoryRegion(
                "NETWORK_FLASH",
                NordicMemoryRegionKind.NETWORK_FLASH,
                0x01000000L,
                262144L,  // 256 KiB
                true,
                false,
                true,
                false));

            regions.add(new NordicMemoryRegion(
                "NETWORK_SRAM",
                NordicMemoryRegionKind.NETWORK_SRAM,
                0x21000000L,
                65536L,   // 64 KiB
                true,
                true,
                true,
                false));

            regions.add(new NordicMemoryRegion(
                "NETWORK_PERIPHERALS",
                NordicMemoryRegionKind.NETWORK_PERIPHERALS,
                0x41000000L,
                0x00020000L,
                true,
                true,
                false,
                false));
        }

        if (part.exactPart().startsWith("nRF52840")) {
            // QSPI XIP external Flash aperture
            regions.add(new NordicMemoryRegion(
                "QSPI_XIP",
                NordicMemoryRegionKind.QSPI_XIP,
                0x12000000L,
                0x04000000L,  // 64 MiB aperture
                true,
                false,
                true,
                false));
        }

        NordicMemoryPlan plan = new NordicMemoryPlan(part, regions);
        plan.validate();
        return plan;
    }
}
