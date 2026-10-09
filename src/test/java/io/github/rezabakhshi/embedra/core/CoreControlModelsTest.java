package io.github.rezabakhshi.embedra.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticSeverity;
import io.github.rezabakhshi.embedra.core.io.BoundedLittleEndianReader;
import io.github.rezabakhshi.embedra.core.io.SourceRange;
import io.github.rezabakhshi.embedra.core.model.Confidence;
import io.github.rezabakhshi.embedra.core.model.Evidence;
import io.github.rezabakhshi.embedra.core.model.EvidenceKind;
import java.time.Duration;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class CoreControlModelsTest {
    @Test
    void cancellationIsCooperativeAndProducesAStableDiagnostic() {
        CancellationSource source = new CancellationSource();
        BoundedLittleEndianReader reader = new BoundedLittleEndianReader(
            new byte[] {1}, new SourceRange(0, 1), ParserLimits.defaults(), source.token());

        assertFalse(source.token().isCancellationRequested());
        source.cancel();
        assertTrue(source.token().isCancellationRequested());

        DiagnosticException failure = assertThrows(DiagnosticException.class, reader::readUnsignedByte);
        assertEquals(DiagnosticCode.CANCELLED, failure.diagnostic().code());
        assertEquals("CORE_CANCELLED", failure.diagnostic().code().id());
        assertEquals(0, reader.sourcePosition());
    }

    @Test
    void parserLimitsArePositiveAndImmutable() {
        ParserLimits defaults = ParserLimits.defaults();
        ParserLimits changed = defaults.withMaxAllocationBytes(64);

        assertEquals(64, changed.maxAllocationBytes());
        assertTrue(defaults.maxAllocationBytes() > changed.maxAllocationBytes());
        assertThrows(IllegalArgumentException.class, () -> new ParserLimits(
            0, 1, 1, 1, 1, Duration.ofSeconds(1)));
        assertThrows(IllegalArgumentException.class, () -> new ParserLimits(
            1, 0, 1, 1, 1, Duration.ofSeconds(1)));
        assertThrows(IllegalArgumentException.class, () -> new ParserLimits(
            1, 1, 0, 1, 1, Duration.ofSeconds(1)));
        assertThrows(IllegalArgumentException.class, () -> new ParserLimits(
            1, 1, 1, 0, 1, Duration.ofSeconds(1)));
        assertThrows(IllegalArgumentException.class, () -> new ParserLimits(
            1, 1, 1, 1, 0, Duration.ofSeconds(1)));
        assertThrows(IllegalArgumentException.class, () -> new ParserLimits(
            1, 1, 1, 1, 1, Duration.ZERO));
        assertThrows(IllegalArgumentException.class, () -> new ParserLimits(
            1, 1, 1, 1, 1, Duration.ofSeconds(-1)));
        assertThrows(NullPointerException.class, () -> new ParserLimits(1, 1, 1, 1, 1, null));
    }

    @Test
    void diagnosticsRequireCodesSeveritiesAndMessages() {
        SourceRange location = new SourceRange(3, 1);
        Diagnostic diagnostic = new Diagnostic(DiagnosticCode.INVALID_MODEL,
            DiagnosticSeverity.WARNING, "Invalid relation", Optional.of(location));

        assertEquals(Optional.of(location), diagnostic.sourceRange());
        assertEquals("CORE_INVALID_MODEL", diagnostic.code().id());
        assertEquals("PLUGIN_MANIFEST_INVALID", DiagnosticCode.PLUGIN_MANIFEST_INVALID.id());
        assertEquals("PLUGIN_SCHEMA_UNSUPPORTED", DiagnosticCode.PLUGIN_SCHEMA_UNSUPPORTED.id());
        assertEquals("PLUGIN_EXECUTION_FAILED", DiagnosticCode.PLUGIN_EXECUTION_FAILED.id());
        assertEquals("PLUGIN_TIMEOUT", DiagnosticCode.PLUGIN_TIMEOUT.id());
        assertEquals("PLUGIN_LIMIT_EXCEEDED", DiagnosticCode.PLUGIN_LIMIT_EXCEEDED.id());
        assertEquals("PLUGIN_PATH_UNSAFE", DiagnosticCode.PLUGIN_PATH_UNSAFE.id());
        assertEquals("CRYPTO_PERIPHERAL_INVALID", DiagnosticCode.CRYPTO_PERIPHERAL_INVALID.id());
        assertEquals("CRYPTO_CALLGRAPH_EXCEEDED", DiagnosticCode.CRYPTO_CALLGRAPH_EXCEEDED.id());
        assertEquals("CRYPTO_DATAFLOW_ERROR", DiagnosticCode.CRYPTO_DATAFLOW_ERROR.id());
        assertThrows(IllegalArgumentException.class, () -> new Diagnostic(
            DiagnosticCode.INVALID_MODEL, DiagnosticSeverity.ERROR, " ", Optional.empty()));
    }

    @Test
    void evidenceSeparatesProvenanceFromConfidence() {
        Evidence evidence = new Evidence(EvidenceKind.DOCUMENTED_FIELD,
            "ESP image header", "Encoded load address");

        assertEquals(EvidenceKind.DOCUMENTED_FIELD, evidence.kind());
        assertEquals("ESP image header", evidence.source());
        assertEquals(Confidence.VERIFIED, Confidence.valueOf("VERIFIED"));
        assertEquals(Confidence.DERIVED, Confidence.valueOf("DERIVED"));
        assertEquals(Confidence.HEURISTIC, Confidence.valueOf("HEURISTIC"));
        assertEquals(Confidence.USER_SELECTED, Confidence.valueOf("USER_SELECTED"));
        assertEquals(Confidence.UNKNOWN, Confidence.valueOf("UNKNOWN"));
        assertThrows(IllegalArgumentException.class, () -> new Evidence(
            EvidenceKind.HEURISTIC, "", "candidate"));
        assertThrows(IllegalArgumentException.class, () -> new Evidence(
            EvidenceKind.HEURISTIC, "source", ""));
    }
}
