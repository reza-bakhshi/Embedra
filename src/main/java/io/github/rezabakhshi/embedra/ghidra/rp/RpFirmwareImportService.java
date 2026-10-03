package io.github.rezabakhshi.embedra.ghidra.rp;

import generic.jar.ResourceFile;
import ghidra.framework.Application;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import io.github.rezabakhshi.embedra.analyzers.rp.RpAnalysisContext;
import io.github.rezabakhshi.embedra.analyzers.rp.RpComponentEnrichmentAnalyzer;
import io.github.rezabakhshi.embedra.analyzers.rp.RpComponentEnrichmentReport;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.formats.rp.uf2.RpUf2Block;
import io.github.rezabakhshi.embedra.formats.rp.uf2.RpUf2Family;
import io.github.rezabakhshi.embedra.formats.rp.uf2.RpUf2Image;
import io.github.rezabakhshi.embedra.formats.rp.uf2.RpUf2Parser;
import io.github.rezabakhshi.embedra.formats.rp.uf2.RpUf2Segment;
import io.github.rezabakhshi.embedra.ghidra.rp.pio.RpPioApplicator;
import io.github.rezabakhshi.embedra.targets.rp.RpTargetProvider;
import io.github.rezabakhshi.embedra.targets.rp.RpTargetResolver;
import io.github.rezabakhshi.embedra.targets.rp.binaryinfo.RpBinaryInfoParser;
import io.github.rezabakhshi.embedra.targets.rp.binaryinfo.RpBinaryInfoResult;
import io.github.rezabakhshi.embedra.targets.rp.board.RpBoardPlan;
import io.github.rezabakhshi.embedra.targets.rp.boot.RpBootMetadata;
import io.github.rezabakhshi.embedra.targets.rp.boot.RpBootMetadataParser;
import io.github.rezabakhshi.embedra.targets.rp.catalog.RpBoardProfile;
import io.github.rezabakhshi.embedra.targets.rp.catalog.RpDeviceCatalog;
import io.github.rezabakhshi.embedra.targets.rp.catalog.RpDeviceCatalogLoader;
import io.github.rezabakhshi.embedra.targets.rp.pio.RpPioProgram;
import io.github.rezabakhshi.embedra.targets.rp.pio.RpPioScanner;
import java.io.File;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * High-level orchestration service for importing Raspberry Pi firmware into Ghidra.
 */
public final class RpFirmwareImportService {

    private final RpTargetResolver resolver;

    private final RpFirmwareMapper mapper;

    private final RpBinaryInfoParser binaryInfoParser;

    private final RpComponentEnrichmentAnalyzer componentAnalyzer;

    public RpFirmwareImportService() {
        this(new RpTargetResolver(loadDefaultCatalogSafe()), new RpFirmwareMapper());
    }

    public static Optional<Path> resolveDefaultCatalogDirectory() {
        try {
            if (Application.isInitialized()) {
                ResourceFile module = Application.getModuleContainingClass(RpFirmwareLoader.class);
                if (module != null) {
                    ResourceFile catalogFile = new ResourceFile(module, "catalogs/rp/2026-10-02/catalog.json");
                    if (catalogFile.isFile()) {
                        File extracted = catalogFile.getFile(true);
                        return Optional.of(extracted.toPath().getParent());
                    }
                }
            }
        } catch (Throwable ignored) {
            // Application not initialized or running outside Ghidra module
        }
        String project = System.getProperty("embedra.projectDir", "");
        if (!project.isBlank()) {
            Path directory = Path.of(project, "catalogs", "rp", "2026-10-02");
            if (Files.isRegularFile(directory.resolve("catalog.json"))) {
                return Optional.of(directory);
            }
        }
        Path local = Path.of("catalogs/rp/2026-10-02");
        if (Files.isRegularFile(local.resolve("catalog.json"))) {
            return Optional.of(local);
        }
        return Optional.empty();
    }

    public static RpDeviceCatalog loadDefaultCatalogSafe() {
        try {
            Optional<Path> dir = resolveDefaultCatalogDirectory();
            if (dir.isPresent()) {
                return RpDeviceCatalogLoader.load(dir.get(), ParserLimits.defaults(), CancellationToken.none());
            }
        } catch (Throwable ignored) {
            // Return empty catalog on failure to prevent loader instantiation crashes
        }
        return RpDeviceCatalog.empty();
    }

    public RpFirmwareImportService(RpTargetResolver resolver, RpFirmwareMapper mapper) {
        this(resolver, mapper, new RpBinaryInfoParser(), new RpComponentEnrichmentAnalyzer());
    }

    public RpFirmwareImportService(
            RpTargetResolver resolver,
            RpFirmwareMapper mapper,
            RpBinaryInfoParser binaryInfoParser,
            RpComponentEnrichmentAnalyzer componentAnalyzer) {
        this.resolver = Objects.requireNonNull(resolver, "resolver must not be null");
        this.mapper = Objects.requireNonNull(mapper, "mapper must not be null");
        this.binaryInfoParser = Objects.requireNonNull(binaryInfoParser, "binaryInfoParser must not be null");
        this.componentAnalyzer = Objects.requireNonNull(componentAnalyzer, "componentAnalyzer must not be null");
    }

    public RpImportReport importFirmware(
            Program program,
            byte[] input,
            String targetPartOption,
            TaskMonitor monitor) throws RpMappingException, CancelledException {
        return importFirmware(program, input, targetPartOption, null, monitor);
    }

    public RpImportReport importFirmware(
            Program program,
            byte[] input,
            String targetPartOption,
            String boardProfileOption,
            TaskMonitor monitor) throws RpMappingException, CancelledException {
        Objects.requireNonNull(program, "program must not be null");
        Objects.requireNonNull(input, "input must not be null");
        Objects.requireNonNull(monitor, "monitor must not be null");

        monitor.checkCancelled();

        boolean isUf2 = isUf2Format(input);
        List<RpUf2Segment> segments;
        String containerFormat;
        String detectedPart = targetPartOption != null && !targetPartOption.isBlank()
                ? targetPartOption.trim()
                : null;

        if (isUf2) {
            containerFormat = "UF2";
            try {
                RpUf2Image image = RpUf2Parser.parse(input, ParserLimits.defaults(), monitor::isCancelled);
                if (detectedPart == null) {
                    detectedPart = partFromFamily(image.family());
                }
                segments = image.segments();
            } catch (DiagnosticException e) {
                throw new RpMappingException(e.diagnostic().code(), e.getMessage(), e);
            }
        } else {
            containerFormat = "RAW_BINARY";
            // Raw binary targeting flash base 0x10000000
            segments = List.of(new RpUf2Segment(RpBootMetadataParser.FLASH_BASE, input, Optional.empty()));
        }

        RpBootMetadata bootMetadata;
        try {
            bootMetadata = RpBootMetadataParser.parse(segments, detectedPart);
        } catch (DiagnosticException e) {
            throw new RpMappingException(e.diagnostic().code(), e.getMessage(), e);
        }

        // 1. Parse Pico SDK Binary Info block
        RpBinaryInfoResult binaryInfo;
        try {
            binaryInfo = binaryInfoParser.parse(segments, ParserLimits.defaults(), monitor::isCancelled);
        } catch (DiagnosticException e) {
            binaryInfo = RpBinaryInfoResult.notPresent();
        }

        // 2. Resolve board profile (from option or binary info)
        String boardId = null;
        if (boardProfileOption != null && !boardProfileOption.isBlank()) {
            boardId = boardProfileOption.trim();
        } else if (binaryInfo.present() && binaryInfo.picoBoard().isPresent()) {
            String boardName = binaryInfo.picoBoard().get();
            // Match against catalog board profile ID
            if (resolver.catalog().findBoardProfile(boardName).isPresent()) {
                boardId = boardName;
            }
        }

        if (detectedPart == null && boardId != null) {
            Optional<RpBoardProfile> profileOpt = resolver.catalog().findBoardProfile(boardId);
            if (profileOpt.isPresent()) {
                detectedPart = profileOpt.get().siliconPart();
            }
        }

        if (detectedPart == null) {
            detectedPart = bootMetadata.series();
            if ("RP2350".equals(detectedPart) && input.length <= 2097152 && targetPartOption != null
                    && targetPartOption.toUpperCase().contains("2354")) {
                detectedPart = "RP2354A";
            } else if ("RP2350".equals(detectedPart)) {
                detectedPart = "RP2350A";
            }
        }

        Optional<RpBoardPlan> boardPlan = Optional.empty();
        RpTargetProvider provider;

        if (boardId != null) {
            try {
                Optional<RpTargetResolver.RpTargetResolution> resOpt = resolver.resolveTarget(detectedPart, boardId);
                if (resOpt.isEmpty()) {
                    throw new RpMappingException(DiagnosticCode.RP_BOARD_MISMATCH,
                            "Board profile " + boardId + " is incompatible with silicon part " + detectedPart);
                }
                provider = resOpt.get().provider();
                boardPlan = resOpt.get().boardPlan();
            } catch (DiagnosticException e) {
                throw new RpMappingException(e.diagnostic().code(), e.getMessage(), e);
            }
        } else {
            Optional<RpTargetProvider> providerOpt = resolver.resolvePart(detectedPart);
            if (providerOpt.isEmpty()) {
                throw new RpMappingException(DiagnosticCode.RP_TARGET_UNSUPPORTED,
                        "No supported Raspberry Pi target provider found for part: " + detectedPart);
            }
            provider = providerOpt.get();
        }

        RpImportReport report = mapper.map(program, segments, provider, bootMetadata, containerFormat, monitor);

        // 3. Run component detectors (TinyUSB, lwIP, CYW43)
        List<String> symbols = new ArrayList<>();
        if (program.getSymbolTable() != null) {
            for (Symbol sym : program.getSymbolTable().getAllSymbols(false)) {
                symbols.add(sym.getName());
            }
        }
        RpAnalysisContext analysisContext = RpAnalysisContext.fromSegments(segments, symbols);
        RpComponentEnrichmentReport componentReport;
        try {
            componentReport = componentAnalyzer.analyze(
                    analysisContext, ParserLimits.defaults(), monitor::isCancelled);
        } catch (DiagnosticException e) {
            throw new RpMappingException(e.diagnostic().code(), e.getMessage(), e);
        }

        // 4. Apply enrichments (board options, binary info, component bookmarks)
        RpEnrichmentApplicator.apply(program, boardPlan, binaryInfo, componentReport, monitor);

        // 5. Scan and apply PIO programs and hardware apertures
        try {
            List<RpPioProgram> pioPrograms = RpPioScanner.scan(
                    segments, ParserLimits.defaults(), monitor::isCancelled);
            RpPioApplicator.apply(program, pioPrograms, provider, monitor);
        } catch (DiagnosticException ignored) {
            // Non-fatal PIO scanning failure
        }

        return report;
    }

    public static boolean isUf2Candidate(byte[] input) {
        if (input == null || input.length < RpUf2Block.BLOCK_SIZE) {
            return false;
        }
        ByteBuffer buf = ByteBuffer.wrap(input).order(ByteOrder.LITTLE_ENDIAN);
        long m0 = Integer.toUnsignedLong(buf.getInt());
        long m1 = Integer.toUnsignedLong(buf.getInt());
        long magicEnd = Integer.toUnsignedLong(buf.getInt(RpUf2Block.BLOCK_SIZE - 4));
        return (m0 == RpUf2Block.EXPECTED_MAGIC_START0 && m1 == RpUf2Block.EXPECTED_MAGIC_START1)
                || m1 == RpUf2Block.EXPECTED_MAGIC_START1
                || magicEnd == RpUf2Block.EXPECTED_MAGIC_END;
    }

    public static boolean isUf2Format(byte[] input) {
        if (input == null || input.length < RpUf2Block.BLOCK_SIZE) {
            return false;
        }
        ByteBuffer buf = ByteBuffer.wrap(input).order(ByteOrder.LITTLE_ENDIAN);
        long m0 = Integer.toUnsignedLong(buf.getInt());
        long m1 = Integer.toUnsignedLong(buf.getInt());
        return m0 == RpUf2Block.EXPECTED_MAGIC_START0 && m1 == RpUf2Block.EXPECTED_MAGIC_START1;
    }

    public static String partFromFamily(RpUf2Family family) {
        if (family == RpUf2Family.RP2040) {
            return "RP2040";
        }
        return "RP2350A";
    }

    public RpDeviceCatalog catalog() {
        return loadDefaultCatalogSafe();
    }
}
