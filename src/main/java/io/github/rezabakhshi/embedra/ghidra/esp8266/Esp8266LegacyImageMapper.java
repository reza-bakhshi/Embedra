package io.github.rezabakhshi.embedra.ghidra.esp8266;

import ghidra.framework.store.LockException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.io.AddressRange;
import io.github.rezabakhshi.embedra.formats.esp8266.Esp8266Image;
import io.github.rezabakhshi.embedra.formats.esp8266.Esp8266ImageSegment;
import io.github.rezabakhshi.embedra.ghidra.esp.EspImportReport;
import io.github.rezabakhshi.embedra.ghidra.esp.EspMappedSegmentReport;
import io.github.rezabakhshi.embedra.ghidra.esp.EspMappingException;
import io.github.rezabakhshi.embedra.ghidra.transaction.GhidraProgramTransaction;
import io.github.rezabakhshi.embedra.targets.LanguageSelection;
import io.github.rezabakhshi.embedra.targets.MemoryClassification;
import io.github.rezabakhshi.embedra.targets.esp8266.Esp8266LegacyTargetProvider;
import java.io.ByteArrayInputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.OptionalLong;

/** Transactional Ghidra mapper for validated ESP8266 legacy images. */
public final class Esp8266LegacyImageMapper {
    public static final String PROGRAM_OPTIONS = "Embedra ESP8266 Legacy Import";

    public EspImportReport map(Program program, Esp8266Image image, long flashBase,
            Esp8266LegacyTargetProvider provider, TaskMonitor monitor)
            throws EspMappingException, CancelledException {
        Objects.requireNonNull(program, "program");
        Objects.requireNonNull(image, "image");
        Objects.requireNonNull(provider, "provider");
        Objects.requireNonNull(monitor, "monitor");
        monitor.checkCancelled();
        validateLanguage(program, provider.language());
        List<SegmentPlan> plans = plan(program, image, flashBase, provider);
        if (!provider.validateEntry(image.header().entryPoint(), image).accepted()) {
            throw new EspMappingException(DiagnosticCode.ESP_ENTRY_REJECTED,
                "ESP8266 entry point was rejected by the legacy target provider");
        }

        List<EspMappedSegmentReport> mapped = new ArrayList<>(plans.size());
        try (GhidraProgramTransaction transaction = GhidraProgramTransaction.start(
                program, "Map validated ESP8266 legacy image")) {
            for (SegmentPlan plan : plans) {
                monitor.checkCancelled();
                MemoryBlock block = program.getMemory().createInitializedBlock(plan.name(),
                    plan.start(), new ByteArrayInputStream(plan.segment().data()),
                    plan.segment().length(), monitor, false);
                block.setRead(plan.classification().readable());
                block.setWrite(plan.classification().writable());
                block.setExecute(plan.classification().executable());
                mapped.add(plan.report());
            }
            Address entry = address(program, image.header().entryPoint());
            if (program.getSymbolTable().getPrimarySymbol(entry) == null) {
                program.getSymbolTable().createLabel(entry, "entry", SourceType.IMPORTED);
            }
            program.getSymbolTable().addExternalEntryPoint(entry);
            var options = program.getOptions(PROGRAM_OPTIONS);
            options.setString("Target Provider", provider.providerId());
            options.setString("Image Version", image.header().version().name());
            options.setString("Exact Silicon Identity", "NOT_ENCODED_ESP8266EX_OR_ESP8285");
            if (image.segments().stream().anyMatch(Esp8266ImageSegment::flashMapped)) {
                options.setLong("Explicit Flash Base", flashBase);
            }
            transaction.commit();
        }
        catch (LockException | MemoryConflictException | AddressOverflowException
                | InvalidInputException exception) {
            throw new EspMappingException(DiagnosticCode.ESP_MAPPING_FAILED,
                "Ghidra rejected the validated ESP8266 mapping", exception);
        }
        LanguageSelection language = provider.language();
        return new EspImportReport(true, "esp8266-legacy-family", language.languageId(),
            language.compilerSpecId(), mapped,
            OptionalLong.of(image.header().entryPoint()));
    }

    private static List<SegmentPlan> plan(Program program, Esp8266Image image,
            long flashBase, Esp8266LegacyTargetProvider provider)
            throws EspMappingException {
        List<SegmentPlan> plans = new ArrayList<>();
        for (Esp8266ImageSegment segment : image.segments()) {
            long loadAddress;
            try {
                loadAddress = segment.resolveLoadAddress(flashBase);
            }
            catch (IllegalArgumentException exception) {
                throw new EspMappingException(DiagnosticCode.ESP_MAPPING_FAILED,
                    exception.getMessage(), exception);
            }
            AddressRange target = new AddressRange("default", loadAddress,
                segment.length());
            MemoryClassification classification = provider.classify(target);
            if (!classification.mappable()) {
                throw new EspMappingException(DiagnosticCode.ESP_MAPPING_FAILED,
                    "ESP8266 segment is outside the pinned memory map at "
                        + hex(loadAddress));
            }
            Address start = address(program, loadAddress);
            Address end = address(program, loadAddress + segment.length() - 1);
            for (MemoryBlock existing : program.getMemory().getBlocks()) {
                if (overlaps(start, end, existing)) {
                    throw new EspMappingException(DiagnosticCode.ESP_MAPPING_CONFLICT,
                        "Existing memory conflicts with ESP8266 segment at "
                            + hex(loadAddress));
                }
            }
            String name = "esp8266_segment_" + segment.index() + "_"
                + classification.kind().name().toLowerCase(Locale.ROOT);
            plans.add(new SegmentPlan(segment, loadAddress, classification, name, start));
        }
        return List.copyOf(plans);
    }

    private static void validateLanguage(Program program, LanguageSelection language)
            throws EspMappingException {
        if (!program.getLanguageID().getIdAsString().equals(language.languageId())
            || !program.getCompilerSpec().getCompilerSpecID().getIdAsString()
                .equals(language.compilerSpecId())) {
            throw new EspMappingException(DiagnosticCode.ESP_LANGUAGE_MISMATCH,
                "Program language/compiler does not match the ESP8266 provider");
        }
    }

    private static boolean overlaps(Address start, Address end, MemoryBlock existing) {
        return start.getAddressSpace().equals(existing.getStart().getAddressSpace())
            && start.compareTo(existing.getEnd()) <= 0
            && existing.getStart().compareTo(end) <= 0;
    }

    private static Address address(Program program, long offset)
            throws EspMappingException {
        try {
            return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
        }
        catch (RuntimeException exception) {
            throw new EspMappingException(DiagnosticCode.ESP_MAPPING_FAILED,
                "ESP8266 address is outside the program address space: " + hex(offset),
                exception);
        }
    }

    private static String hex(long address) {
        return String.format(Locale.ROOT, "0x%08x", address);
    }

    private record SegmentPlan(
            Esp8266ImageSegment segment,
            long loadAddress,
            MemoryClassification classification,
            String name,
            Address start) {
        private EspMappedSegmentReport report() {
            return new EspMappedSegmentReport(segment.index(), name, loadAddress,
                segment.length(), segment.dataSourceRange(), classification.kind(),
                classification.readable(), classification.writable(),
                classification.executable());
        }
    }
}
