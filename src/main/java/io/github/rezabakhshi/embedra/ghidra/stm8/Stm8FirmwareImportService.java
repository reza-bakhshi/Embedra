package io.github.rezabakhshi.embedra.ghidra.stm8;

import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.targets.stm8.catalog.Stm8CatalogRegistry;
import io.github.rezabakhshi.embedra.targets.stm8.catalog.Stm8PartRecord;
import io.github.rezabakhshi.embedra.targets.stm8.memory.Stm8MemoryPlan;
import io.github.rezabakhshi.embedra.targets.stm8.memory.Stm8MemoryPlanner;
import io.github.rezabakhshi.embedra.targets.stm8.peripheral.Stm8DevicePackRegistry;
import io.github.rezabakhshi.embedra.targets.stm8.peripheral.Stm8PeripheralPack;
import io.github.rezabakhshi.embedra.targets.stm8.vector.Stm8VectorTable;
import io.github.rezabakhshi.embedra.targets.stm8.vector.Stm8VectorTableParser;
import java.io.IOException;
import java.util.Objects;
import java.util.Optional;

/**
 * Service orchestrating the import and mapping of STM8 firmware images into Ghidra programs.
 */
public final class Stm8FirmwareImportService {

    private final Stm8CatalogRegistry catalogRegistry;

    private final Stm8DevicePackRegistry packRegistry;

    private final Stm8FirmwareMapper mapper;

    public Stm8FirmwareImportService() {
        this(loadDefaultCatalogSafe(), loadDefaultPacksSafe(), new Stm8FirmwareMapper());
    }

    private static Stm8CatalogRegistry loadDefaultCatalogSafe() {
        try {
            return Stm8CatalogRegistry.loadDefault();
        } catch (DiagnosticException e) {
            return new Stm8CatalogRegistry(java.util.List.of());
        }
    }

    private static Stm8DevicePackRegistry loadDefaultPacksSafe() {
        try {
            return Stm8DevicePackRegistry.loadDefault();
        } catch (DiagnosticException e) {
            return new Stm8DevicePackRegistry(java.util.List.of());
        }
    }

    public Stm8FirmwareImportService(
            Stm8CatalogRegistry catalogRegistry,
            Stm8DevicePackRegistry packRegistry,
            Stm8FirmwareMapper mapper) {
        this.catalogRegistry = Objects.requireNonNull(catalogRegistry, "catalogRegistry");
        this.packRegistry = Objects.requireNonNull(packRegistry, "packRegistry");
        this.mapper = Objects.requireNonNull(mapper, "mapper");
    }

    public Stm8CatalogRegistry catalogRegistry() {
        return catalogRegistry;
    }

    public Stm8DevicePackRegistry packRegistry() {
        return packRegistry;
    }

    public Stm8FirmwareMapper mapper() {
        return mapper;
    }

    /**
     * Imports STM8 firmware into the target program.
     */
    public Stm8ImportReport importFirmware(
            Program program,
            byte[] input,
            String targetPartOverride,
            ParserLimits limits,
            TaskMonitor monitor) throws Stm8MappingException, CancelledException {
        Objects.requireNonNull(program, "program");
        Objects.requireNonNull(input, "input");
        Objects.requireNonNull(limits, "limits");
        Objects.requireNonNull(monitor, "monitor");

        monitor.checkCancelled();

        // 1. Language validation
        String langId = program.getLanguageID().getIdAsString();
        if (!langId.toUpperCase().startsWith("STM8")) {
            throw new Stm8MappingException(
                DiagnosticCode.STM8_LANGUAGE_MISMATCH,
                "Current program language is " + langId
                    + ", but STM8 loader requires an 8-bit STM8 processor definition"
            );
        }

        // 2. Decode input
        Stm8InputDecoder.DecodedFirmware decoded = Stm8InputDecoder.decode(input, limits);

        // 3. Resolve target silicon part
        Stm8PartRecord part = resolvePart(decoded, targetPartOverride);

        // 4. Compute memory plan
        Stm8MemoryPlan memoryPlan;
        try {
            memoryPlan = Stm8MemoryPlanner.plan(part, limits, monitor::isCancelled);
        } catch (DiagnosticException e) {
            throw new Stm8MappingException(DiagnosticCode.STM8_MAPPING_CONFLICT, e.getMessage(), e);
        }

        // 5. Parse vector table from flash bytes if available
        Stm8VectorTable vectorTable = null;
        if (decoded.flashBytes().length >= 4) {
            try {
                vectorTable = Stm8VectorTableParser.parse(
                    decoded.flashBytes(),
                    part,
                    limits,
                    monitor::isCancelled
                );
            } catch (DiagnosticException ignored) {
                // Flash bytes did not contain a full 32-vector table
            }
        }

        // 6. Resolve peripheral pack for family
        Stm8PeripheralPack peripheralPack = packRegistry.packForPart(part).orElse(null);

        monitor.checkCancelled();

        // 7. Map memory blocks, vectors, and registers into Ghidra
        return mapper.map(
            program,
            part,
            memoryPlan,
            vectorTable,
            peripheralPack,
            decoded.flashBytes(),
            decoded.format(),
            monitor
        );
    }

    private Stm8PartRecord resolvePart(Stm8InputDecoder.DecodedFirmware decoded, String targetPartOverride)
            throws Stm8MappingException {
        if (targetPartOverride != null && !targetPartOverride.isBlank()) {
            Optional<Stm8PartRecord> opt = catalogRegistry.findPart(targetPartOverride.trim());
            if (opt.isPresent()) {
                return opt.get();
            }
            throw new Stm8MappingException(
                DiagnosticCode.STM8_TARGET_UNSUPPORTED,
                "Specified STM8 target part override not found in catalog: " + targetPartOverride
            );
        }

        // Default heuristic: pick representative part matching flash size
        int flashBytes = decoded.flashBytes().length;
        if (flashBytes <= 8192) {
            return catalogRegistry.findPart("STM8S003F3P6")
                .or(() -> catalogRegistry.findPart("STM8S103F3P6"))
                .orElseThrow(() -> new Stm8MappingException(
                    DiagnosticCode.STM8_TARGET_UNSUPPORTED, "No default STM8 part found for 8KB flash"));
        } else if (flashBytes <= 32768) {
            return catalogRegistry.findPart("STM8S105K4T6C")
                .or(() -> catalogRegistry.findPart("STM8L151C8T6"))
                .orElseGet(() -> catalogRegistry.listParts().getFirst());
        } else {
            return catalogRegistry.findPart("STM8S208RBT6")
                .or(() -> catalogRegistry.findPart("STM8AF5288TAY"))
                .orElseGet(() -> catalogRegistry.listParts().getFirst());
        }
    }
}
