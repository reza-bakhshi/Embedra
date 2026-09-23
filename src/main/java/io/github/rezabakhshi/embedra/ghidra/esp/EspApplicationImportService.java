package io.github.rezabakhshi.embedra.ghidra.esp;

import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.core.io.AddressRange;
import io.github.rezabakhshi.embedra.core.model.Evidence;
import io.github.rezabakhshi.embedra.core.model.EvidenceKind;
import io.github.rezabakhshi.embedra.core.report.CanonicalReport;
import io.github.rezabakhshi.embedra.formats.esp.EspAppDescription;
import io.github.rezabakhshi.embedra.formats.esp.EspAppDescriptionExtractor;
import io.github.rezabakhshi.embedra.formats.esp.EspAppDescriptionResult;
import io.github.rezabakhshi.embedra.formats.esp.EspImage;
import io.github.rezabakhshi.embedra.formats.esp.EspImageParser;
import io.github.rezabakhshi.embedra.targets.esp.Esp32S3TargetProvider;
import io.github.rezabakhshi.embedra.targets.esp.EspressifChipIdRegistry;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/** One shared deterministic import workflow for Ghidra GUI and headless callers. */
public final class EspApplicationImportService {
    private static final int ESP32_S3_CHIP_ID = 9;

    private static final String PROVIDER_VERSION = "esptool-v5.4.0+esp-idf-v6.0";

    private static final String PROVIDER_IDENTITY =
        "esp32s3|chip-id-9|Xtensa:LE:32:esp32s3|default|" + PROVIDER_VERSION;

    private static final Evidence STRUCTURE_EVIDENCE = new Evidence(
        EvidenceKind.VERIFIED_CHECKSUM, "validated ESP application image",
        "Header, segments, checksum, optional digest, and entry were validated");

    private static final Evidence MAPPING_EVIDENCE = new Evidence(
        EvidenceKind.DOCUMENTED_FIELD, "ESP application segment header",
        "Encoded load address and length were retained exactly");

    private final Esp32S3TargetProvider targetProvider = new Esp32S3TargetProvider(
        EspressifChipIdRegistry.loadBundled());

    public EspImportWorkflowResult importImage(Program program, byte[] input,
            TaskMonitor monitor) throws DiagnosticException, EspMappingException,
            CancelledException {
        return importImage(program, input, monitor, Optional.empty());
    }

    public EspImportWorkflowResult importImage(Program program, byte[] input,
            TaskMonitor monitor, EspFlashProgramProvenance provenance)
            throws DiagnosticException, EspMappingException, CancelledException {
        return importImage(program, input, monitor,
            Optional.of(Objects.requireNonNull(provenance, "provenance")));
    }

    private EspImportWorkflowResult importImage(Program program, byte[] input,
            TaskMonitor monitor, Optional<EspFlashProgramProvenance> provenance)
            throws DiagnosticException, EspMappingException, CancelledException {
        Objects.requireNonNull(program, "program");
        Objects.requireNonNull(input, "input");
        Objects.requireNonNull(monitor, "monitor");
        CancellationToken cancellation = monitor::isCancelled;
        EspImage image = EspImageParser.parseForChip(input, ESP32_S3_CHIP_ID,
            ParserLimits.defaults(), cancellation);
        EspAppDescriptionResult appDescription = EspAppDescriptionExtractor.extract(image);
        EspImportReport importReport = new EspApplicationImageMapper().map(program, image,
            targetProvider, monitor, provenance);
        CanonicalReport canonicalReport = report(input, importReport, appDescription);
        EspProgramSnapshot snapshot = EspProgramSnapshot.from(image, importReport);
        return new EspImportWorkflowResult(importReport, appDescription, canonicalReport,
            snapshot);
    }

    private static CanonicalReport report(byte[] input, EspImportReport imported,
            EspAppDescriptionResult appDescription) {
        List<CanonicalReport.Mapping> mappings = imported.segments().stream()
            .map(segment -> new CanonicalReport.Mapping(
                "segment-" + segment.index(), segment.sourceRange(),
                new AddressRange("default", segment.loadAddress(), segment.length()),
                permissions(segment), List.of(MAPPING_EVIDENCE)))
            .toList();
        LinkedHashMap<String, String> metadata = new LinkedHashMap<>();
        metadata.put("format", "esp-application-image");
        metadata.put("deviceId", imported.deviceId());
        metadata.put("languageId", imported.languageId());
        metadata.put("compilerSpecId", imported.compilerSpecId());
        appDescription.description().ifPresent(description -> addMetadata(metadata,
            description));
        CanonicalReport.Component provider = new CanonicalReport.Component(
            "target.esp32s3", PROVIDER_VERSION,
            sha256(PROVIDER_IDENTITY.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        CanonicalReport.Validation validation = new CanonicalReport.Validation(
            "ESP_IMAGE_VALID", "PASS", "ESP application image is structurally valid",
            List.of(STRUCTURE_EVIDENCE));
        CanonicalReport.AppliedSymbol entry = new CanonicalReport.AppliedSymbol(
            "entry", "global", "default", imported.entryPoint().orElseThrow(),
            "target.esp32s3");
        return CanonicalReport.create("embedra-development",
            List.of(new CanonicalReport.Input("esp-application-image", sha256(input),
                input.length)),
            List.of(provider), List.of(), List.of(validation), mappings,
            List.of(entry), List.of(), metadata, Optional.empty(), List.of(),
            appDescription.diagnostics(),
            new CanonicalReport.Reproducibility(true, List.of("esp_app_desc")));
    }

    private static void addMetadata(Map<String, String> metadata,
            EspAppDescription description) {
        metadata.put("app.projectName", description.projectName());
        metadata.put("app.version", description.version());
        metadata.put("app.idfVersion", description.idfVersion());
        metadata.put("app.secureVersion", Long.toString(description.secureVersion()));
        metadata.put("app.elfSha256", HexFormat.of().formatHex(
            description.appElfSha256()));
    }

    private static String permissions(EspMappedSegmentReport segment) {
        return new String(new char[] {
            segment.readable() ? 'r' : '-',
            segment.writable() ? 'w' : '-',
            segment.executable() ? 'x' : '-'
        });
    }

    private static String sha256(byte[] input) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(input));
        }
        catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("Required SHA-256 implementation unavailable",
                exception);
        }
    }
}
