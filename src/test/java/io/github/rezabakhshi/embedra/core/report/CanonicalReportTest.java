package io.github.rezabakhshi.embedra.core.report;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticSeverity;
import io.github.rezabakhshi.embedra.core.io.AddressRange;
import io.github.rezabakhshi.embedra.core.io.SourceRange;
import io.github.rezabakhshi.embedra.core.model.Confidence;
import io.github.rezabakhshi.embedra.core.model.Evidence;
import io.github.rezabakhshi.embedra.core.model.EvidenceKind;
import io.github.rezabakhshi.embedra.core.model.ExecutionTopology;
import io.github.rezabakhshi.embedra.core.model.FirmwareSource;
import io.github.rezabakhshi.embedra.core.model.ProcessorKind;
import io.github.rezabakhshi.embedra.core.model.ProcessorNode;
import io.github.rezabakhshi.embedra.core.model.ProgramStrategy;
import io.github.rezabakhshi.embedra.core.model.SecurityDomain;
import io.github.rezabakhshi.embedra.test.SnapshotAssertions;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TimeZone;
import org.junit.jupiter.api.Test;

class CanonicalReportTest {
    private static final String SHA_A = "a".repeat(64);

    private static final String SHA_B = "b".repeat(64);

    private static final Evidence EVIDENCE = new Evidence(
        EvidenceKind.VERIFIED_CHECKSUM, "synthetic fixture", "digest verified");

    @Test
    void reportIsDeterministicAndExcludesHostAndTimeState() {
        HashMap<String, String> metadata = new HashMap<>();
        metadata.put("project", "fixture");
        metadata.put("format", "synthetic");
        CanonicalReport report = report(List.of(
            new CanonicalReport.Input("input-b", SHA_B, 2),
            new CanonicalReport.Input("input-a", SHA_A, 1)), metadata);
        CanonicalReport reordered = report(List.of(
            new CanonicalReport.Input("input-a", SHA_A, 1),
            new CanonicalReport.Input("input-b", SHA_B, 2)), Map.of(
                "format", "synthetic", "project", "fixture"));

        String json = report.toCanonicalJson();

        assertEquals(json, reordered.toCanonicalJson());
        SnapshotAssertions.assertMatches("snapshots/canonical-report.json", json);
        assertFalse(json.contains("timestamp"));
        assertFalse(json.contains("hostPath"));
    }

    @Test
    void reportRejectsUnknownSchemaAndMalformedDigests() {
        assertThrows(IllegalArgumentException.class, () -> new CanonicalReport.Input(
            "input", "not-a-sha256", 1));
        assertThrows(IllegalArgumentException.class, () -> new CanonicalReport.Input(
            "input", SHA_A, -1));
        assertThrows(IllegalArgumentException.class, () -> CanonicalReport.create(
            " ", List.of(), List.of(), List.of(), List.of(), List.of(), List.of(), List.of(), Map.of(),
            Optional.empty(), List.of(), List.of(),
            new CanonicalReport.Reproducibility(true, List.of())));
        assertThrows(IllegalArgumentException.class, () -> new CanonicalReport(
            "urn:embedra:schema:canonical-report:999", "build", List.of(), List.of(), List.of(),
            List.of(), List.of(), List.of(), List.of(), Map.of(), Optional.empty(), List.of(), List.of(),
            new CanonicalReport.Reproducibility(true, List.of())));
        assertThrows(IllegalArgumentException.class, () -> new CanonicalReport.AppliedSymbol(
            "symbol", "global", "cpu", -1, "fixture"));
    }

    @Test
    void snapshotHelperNeverCreatesMissingOrUpdatedOracles() {
        assertThrows(AssertionError.class,
            () -> SnapshotAssertions.assertMatches("snapshots/missing.json", "{}\n"));
    }

    @Test
    void reportSerializesOptionalTopologyAndAbsentLocations() {
        CanonicalReport base = report(List.of(new CanonicalReport.Input("input", SHA_A, 1)), Map.of());
        ProcessorNode processor = new ProcessorNode("cpu", ProcessorKind.CPU_CORE,
            Optional.of("synthetic-isa"), Optional.of("language"), Optional.of("default"),
            "application", SecurityDomain.unknown(), "soc", Set.of("cpu"), List.of(),
            FirmwareSource.SHARED_IMAGE, Confidence.UNKNOWN, List.of(EVIDENCE));
        ExecutionTopologyReport topology = ExecutionTopologyReport.from(new ExecutionTopology(
            List.of(processor), List.of(), List.of(), List.of(), List.of(), ProgramStrategy.SHARED_PROGRAM));
        CanonicalReport.Finding finding = new CanonicalReport.Finding(
            "without-address", "synthetic", "metadata", "INFO", Confidence.UNKNOWN,
            Optional.empty(), "No address", false);
        Diagnostic diagnostic = new Diagnostic(DiagnosticCode.INVALID_MODEL,
            DiagnosticSeverity.INFO, "No source location", Optional.empty());
        CanonicalReport report = new CanonicalReport(CanonicalReport.SCHEMA_ID, base.toolBuild(),
            base.inputs(), base.providers(), base.packs(), base.validations(), base.mappings(),
            base.appliedSymbols(), base.appliedTypes(), base.metadata(), Optional.of(topology),
            List.of(finding), List.of(diagnostic),
            base.reproducibility());

        String json = report.toCanonicalJson();

        assertFalse(json.contains("\"executionTopology\":null"));
        assertFalse(json.contains("\"address\":{\""));
    }

    @Test
    void reportDoesNotDependOnDefaultLocaleOrTimeZone() {
        Locale originalLocale = Locale.getDefault();
        TimeZone originalTimeZone = TimeZone.getDefault();
        CanonicalReport report = report(
            List.of(new CanonicalReport.Input("input", SHA_A, 1)), Map.of("key", "value"));

        try {
            Locale.setDefault(Locale.forLanguageTag("tr-TR"));
            TimeZone.setDefault(TimeZone.getTimeZone("Asia/Tehran"));
            String first = report.toCanonicalJson();
            Locale.setDefault(Locale.JAPAN);
            TimeZone.setDefault(TimeZone.getTimeZone("Pacific/Auckland"));

            assertEquals(first, report.toCanonicalJson());
        }
        finally {
            Locale.setDefault(originalLocale);
            TimeZone.setDefault(originalTimeZone);
        }
    }

    private static CanonicalReport report(
            List<CanonicalReport.Input> inputs, Map<String, String> metadata) {
        CanonicalReport.Component provider = new CanonicalReport.Component(
            "provider.synthetic", "1", SHA_A);
        CanonicalReport.Validation validation = new CanonicalReport.Validation(
            "SYNTHETIC_VALID", "PASS", "Synthetic structure is valid", List.of(EVIDENCE));
        CanonicalReport.Mapping mapping = new CanonicalReport.Mapping(
            "segment-0", new SourceRange(0, 4), new AddressRange("cpu", 0x1000, 4),
            "r-x", List.of(EVIDENCE));
        CanonicalReport.Finding finding = new CanonicalReport.Finding(
            "finding-0", "synthetic", "metadata", "INFO", Confidence.VERIFIED,
            Optional.of(new AddressRange("cpu", 0x1000, 1)), "Synthetic finding", false);
        Diagnostic warning = new Diagnostic(DiagnosticCode.INVALID_MODEL,
            DiagnosticSeverity.WARNING, "Synthetic warning", Optional.of(new SourceRange(0, 1)));
        CanonicalReport.AppliedSymbol symbol = new CanonicalReport.AppliedSymbol(
            "reset_handler", "global", "cpu", 0x1000, "provider.synthetic");
        CanonicalReport.AppliedType type = new CanonicalReport.AppliedType(
            "synthetic_header", "/embedra/synthetic", "pack.synthetic");
        return CanonicalReport.create("embedra-test-build", inputs, List.of(provider), List.of(),
            List.of(validation), List.of(mapping), List.of(symbol), List.of(type), metadata,
            Optional.empty(), List.of(finding), List.of(warning),
            new CanonicalReport.Reproducibility(true, List.of("topology")));
    }
}
