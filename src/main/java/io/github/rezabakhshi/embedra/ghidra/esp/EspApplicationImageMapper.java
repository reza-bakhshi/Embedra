package io.github.rezabakhshi.embedra.ghidra.esp;

import ghidra.framework.store.LockException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.formats.esp.EspImage;
import io.github.rezabakhshi.embedra.formats.esp.EspImageSegment;
import io.github.rezabakhshi.embedra.ghidra.transaction.GhidraProgramTransaction;
import io.github.rezabakhshi.embedra.targets.EntryPointDecision;
import io.github.rezabakhshi.embedra.targets.LanguageSelection;
import io.github.rezabakhshi.embedra.targets.MemoryClassification;
import io.github.rezabakhshi.embedra.targets.SupportDecision;
import io.github.rezabakhshi.embedra.targets.esp.Esp32S3TargetProvider;
import java.io.ByteArrayInputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;

/** Transactional translation of validated ESP models into one Ghidra program. */
public final class EspApplicationImageMapper {
    public EspImportReport map(Program program, EspImage image,
            Esp32S3TargetProvider provider, TaskMonitor monitor)
            throws EspMappingException, CancelledException {
        return map(program, image, provider, monitor, Optional.empty());
    }

    public EspImportReport map(Program program, EspImage image,
            Esp32S3TargetProvider provider, TaskMonitor monitor,
            Optional<EspFlashProgramProvenance> flashProvenance)
            throws EspMappingException, CancelledException {
        Objects.requireNonNull(program, "program");
        Objects.requireNonNull(image, "image");
        Objects.requireNonNull(provider, "provider");
        Objects.requireNonNull(monitor, "monitor");
        Objects.requireNonNull(flashProvenance, "flashProvenance");
        monitor.checkCancelled();

        SupportDecision support = provider.supports(image);
        if (!support.supported()) {
            throw new EspMappingException(DiagnosticCode.ESP_TARGET_UNSUPPORTED,
                support.reason());
        }
        LanguageSelection language = provider.language();
        validateProgramLanguage(program, language);

        List<SegmentPlan> plans = planSegments(program, image, provider);
        EntryPointDecision entryDecision = provider.validateEntry(
            image.header().entryPoint(), image);
        if (!entryDecision.accepted()) {
            throw new EspMappingException(DiagnosticCode.ESP_ENTRY_REJECTED,
                entryDecision.reason());
        }

        List<EspMappedSegmentReport> mapped = new ArrayList<>(plans.size());
        try (GhidraProgramTransaction transaction = GhidraProgramTransaction.start(
                program, "Map validated ESP application image")) {
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
            monitor.checkCancelled();
            Address entryAddress = address(program, image.header().entryPoint());
            Symbol existing = program.getSymbolTable().getPrimarySymbol(entryAddress);
            if (existing == null) {
                program.getSymbolTable().createLabel(entryAddress, "entry", SourceType.IMPORTED);
            }
            program.getSymbolTable().addExternalEntryPoint(entryAddress);
            flashProvenance.ifPresent(provenance -> applyProvenance(program,
                provenance));
            transaction.commit();
        }
        catch (LockException | MemoryConflictException | AddressOverflowException
                | InvalidInputException exception) {
            throw new EspMappingException(DiagnosticCode.ESP_MAPPING_FAILED,
                "Ghidra rejected the validated ESP mapping", exception);
        }

        return new EspImportReport(true, support.deviceId().orElseThrow(),
            language.languageId(), language.compilerSpecId(), mapped,
            OptionalLong.of(image.header().entryPoint()));
    }

    private static void applyProvenance(Program program,
            EspFlashProgramProvenance provenance) {
        var options = program.getOptions("Embedra Full Flash Provenance");
        options.setString("Source SHA-256", provenance.sourceSha256());
        options.setLong("Partition Table Offset", provenance.partitionTableOffset());
        options.setLong("Executable Flash Offset", provenance.flashOffset());
        options.setLong("Executable Flash Length", provenance.flashLength());
        options.setString("Executable Role", provenance.role());
        options.setString("Partition Label", provenance.partitionLabel());
    }

    private static void validateProgramLanguage(Program program, LanguageSelection language)
            throws EspMappingException {
        String actualLanguage = program.getLanguageID().getIdAsString();
        String actualCompiler = program.getCompilerSpec().getCompilerSpecID().getIdAsString();
        if (!actualLanguage.equals(language.languageId())
            || !actualCompiler.equals(language.compilerSpecId())) {
            throw new EspMappingException(DiagnosticCode.ESP_LANGUAGE_MISMATCH,
                "Program language/compiler does not match the ESP32-S3 provider");
        }
    }

    private static List<SegmentPlan> planSegments(Program program, EspImage image,
            Esp32S3TargetProvider provider) throws EspMappingException {
        List<SegmentPlan> plans = new ArrayList<>(image.segments().size());
        for (EspImageSegment segment : image.segments()) {
            MemoryClassification classification = provider.classify(segment.targetRange());
            if (!classification.mappable()) {
                throw new EspMappingException(DiagnosticCode.ESP_MAPPING_FAILED,
                    "ESP segment is outside the provider memory map at "
                        + hex(segment.loadAddress()));
            }
            Address start = address(program, segment.loadAddress());
            long endOffset = segment.loadAddress() + segment.length() - 1;
            Address end = address(program, endOffset);
            for (MemoryBlock existing : program.getMemory().getBlocks()) {
                if (overlaps(start, end, existing)) {
                    throw new EspMappingException(DiagnosticCode.ESP_MAPPING_CONFLICT,
                        "Existing memory conflicts with ESP segment at "
                            + hex(segment.loadAddress()));
                }
            }
            String name = "esp_segment_" + segment.index() + "_"
                + classification.kind().name().toLowerCase(Locale.ROOT);
            plans.add(new SegmentPlan(segment, classification, name, start));
        }
        return List.copyOf(plans);
    }

    private static boolean overlaps(Address start, Address end, MemoryBlock existing) {
        return start.getAddressSpace().equals(existing.getStart().getAddressSpace())
            && start.compareTo(existing.getEnd()) <= 0
            && existing.getStart().compareTo(end) <= 0;
    }

    private static Address address(Program program, long offset) throws EspMappingException {
        try {
            return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
        }
        catch (RuntimeException exception) {
            throw new EspMappingException(DiagnosticCode.ESP_MAPPING_FAILED,
                "ESP address is outside the program address space: " + hex(offset),
                exception);
        }
    }

    private static String hex(long address) {
        return String.format(Locale.ROOT, "0x%08x", address);
    }

    private record SegmentPlan(
            EspImageSegment segment,
            MemoryClassification classification,
            String name,
            Address start) {
        private EspMappedSegmentReport report() {
            return new EspMappedSegmentReport(segment.index(), name,
                segment.loadAddress(), segment.length(), segment.dataSourceRange(),
                classification.kind(), classification.readable(), classification.writable(),
                classification.executable());
        }
    }
}
