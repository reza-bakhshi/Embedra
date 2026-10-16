package io.github.rezabakhshi.embedra.ghidra.atmel;

import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.ghidra.atmel.AtmelInputDecoder.DecodedAtmelFirmware;
import io.github.rezabakhshi.embedra.ghidra.atmel.AtmelInputDecoder.DecodedSegment;
import io.github.rezabakhshi.embedra.targets.atmel.catalog.AtmelCatalogRegistry;
import io.github.rezabakhshi.embedra.targets.atmel.catalog.AtmelPartRecord;
import io.github.rezabakhshi.embedra.targets.atmel.memory.AtmelMemoryPlan;
import io.github.rezabakhshi.embedra.targets.atmel.memory.AtmelMemoryPlanner;
import io.github.rezabakhshi.embedra.targets.atmel.peripheral.AtmelDevicePackRegistry;
import io.github.rezabakhshi.embedra.targets.atmel.peripheral.AtmelPeripheralPack;
import io.github.rezabakhshi.embedra.targets.atmel.vector.AtmelVectorTable;
import io.github.rezabakhshi.embedra.targets.atmel.vector.AtmelVectorTableParser;
import java.util.Objects;
import java.util.Optional;

/**
 * Service orchestrating the import and mapping of Atmel / Microchip firmware images into Ghidra programs.
 */
public final class AtmelFirmwareImportService {

    private final AtmelCatalogRegistry catalogRegistry;

    private final AtmelDevicePackRegistry packRegistry;

    private final AtmelFirmwareMapper mapper;

    public AtmelFirmwareImportService() {
        this(loadDefaultCatalogSafe(), loadDefaultPacksSafe(), new AtmelFirmwareMapper());
    }

    public AtmelFirmwareImportService(
            AtmelCatalogRegistry catalogRegistry,
            AtmelDevicePackRegistry packRegistry,
            AtmelFirmwareMapper mapper) {
        this.catalogRegistry = Objects.requireNonNull(catalogRegistry, "catalogRegistry must not be null");
        this.packRegistry = Objects.requireNonNull(packRegistry, "packRegistry must not be null");
        this.mapper = Objects.requireNonNull(mapper, "mapper must not be null");
    }

    public static AtmelCatalogRegistry loadDefaultCatalogSafe() {
        try {
            return AtmelCatalogRegistry.loadDefault();
        } catch (DiagnosticException e) {
            return new AtmelCatalogRegistry(java.util.List.of());
        }
    }

    public static AtmelDevicePackRegistry loadDefaultPacksSafe() {
        try {
            return AtmelDevicePackRegistry.loadDefault();
        } catch (DiagnosticException e) {
            return new AtmelDevicePackRegistry(java.util.List.of());
        }
    }

    public AtmelCatalogRegistry catalogRegistry() {
        return catalogRegistry;
    }

    public AtmelDevicePackRegistry packRegistry() {
        return packRegistry;
    }

    public AtmelFirmwareMapper mapper() {
        return mapper;
    }

    /**
     * Imports Atmel firmware into the target program.
     */
    public AtmelImportReport importFirmware(
            Program program,
            byte[] input,
            String targetPartOverride,
            ParserLimits limits,
            TaskMonitor monitor) throws AtmelMappingException, CancelledException {
        Objects.requireNonNull(program, "program must not be null");
        Objects.requireNonNull(input, "input must not be null");
        Objects.requireNonNull(limits, "limits must not be null");
        Objects.requireNonNull(monitor, "monitor must not be null");

        monitor.checkCancelled();

        // 1. Decode input into segments
        DecodedAtmelFirmware decoded = AtmelInputDecoder.decode(input, limits);

        // 2. Resolve target silicon part
        AtmelPartRecord part = resolvePart(decoded, targetPartOverride);

        // 3. Compute memory plan
        AtmelMemoryPlan memoryPlan;
        try {
            memoryPlan = AtmelMemoryPlanner.plan(part, limits, monitor::isCancelled);
        } catch (DiagnosticException e) {
            throw new AtmelMappingException(DiagnosticCode.ATMEL_MAPPING_CONFLICT, e.getMessage(), e);
        }

        // 4. Parse vector table from primary flash segment if available
        AtmelVectorTable vectorTable = null;
        DecodedSegment flashSeg = findFlashSegment(decoded, part);
        if (flashSeg != null && flashSeg.data().length >= 4) {
            try {
                vectorTable = AtmelVectorTableParser.parse(
                    flashSeg.data(),
                    flashSeg.address(),
                    part,
                    limits,
                    monitor::isCancelled
                );
            } catch (DiagnosticException ignored) {
                // Flash segment did not contain a full valid vector table
            }
        }

        // 5. Resolve peripheral pack for part
        AtmelPeripheralPack peripheralPack = packRegistry.packForPart(part.exactPart()).orElse(null);

        monitor.checkCancelled();

        // 6. Map memory blocks, vectors, and registers into Ghidra
        return mapper.map(
            program,
            part,
            memoryPlan,
            vectorTable,
            peripheralPack,
            decoded,
            monitor
        );
    }

    private DecodedSegment findFlashSegment(DecodedAtmelFirmware decoded, AtmelPartRecord part) {
        for (DecodedSegment seg : decoded.segments()) {
            if (seg.address() == part.flashStart()) {
                return seg;
            }
        }
        if (!decoded.segments().isEmpty()) {
            return decoded.segments().getFirst();
        }
        return null;
    }

    private AtmelPartRecord resolvePart(DecodedAtmelFirmware decoded, String targetPartOverride)
            throws AtmelMappingException {
        if (targetPartOverride != null && !targetPartOverride.isBlank()) {
            Optional<AtmelPartRecord> opt = catalogRegistry.findPart(targetPartOverride.trim());
            if (opt.isPresent()) {
                return opt.get();
            }
            throw new AtmelMappingException(
                DiagnosticCode.ATMEL_TARGET_UNSUPPORTED,
                "Specified Atmel target part override not found in catalog: " + targetPartOverride
            );
        }

        if (decoded.targetHint().isPresent()) {
            Optional<AtmelPartRecord> opt = catalogRegistry.findPart(decoded.targetHint().get());
            if (opt.isPresent()) {
                return opt.get();
            }
        }

        if (decoded.isAvr()) {
            return catalogRegistry.findPart("ATmega328P")
                .orElseGet(AtmelPartRecord::defaultAtmega328p);
        } else {
            return catalogRegistry.findPart("SAMD21G18A")
                .orElseGet(AtmelPartRecord::defaultSamd21g18a);
        }
    }
}
