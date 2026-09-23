package io.github.rezabakhshi.embedra.analyzers.esp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.CancellationSource;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.core.io.SourceRange;
import io.github.rezabakhshi.embedra.core.model.Confidence;
import io.github.rezabakhshi.embedra.formats.esp.EspExecutableRole;
import io.github.rezabakhshi.embedra.formats.esp.EspFlashRange;
import io.github.rezabakhshi.embedra.formats.esp.EspPartitionEntry;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.OptionalLong;
import org.junit.jupiter.api.Test;

class EspFactoryOtaAnalyzerTest {
    @Test
    void distinguishesUnchangedMovedModifiedAddedAndRemovedArtifacts() throws Exception {
        EspFirmwareArtifact factory = artifact("factory", EspExecutableRole.FACTORY,
            0x10000, digest('a'), "2.0.0", 3, EspImageHashState.VERIFIED);
        EspFirmwareArtifact same = artifact("ota_0", EspExecutableRole.OTA,
            0x10000, digest('a'), "2.0.0", 3, EspImageHashState.VERIFIED);
        EspFirmwareArtifact moved = artifact("ota_0", EspExecutableRole.OTA,
            0x210000, digest('a'), "2.0.0", 3, EspImageHashState.VERIFIED);
        EspFirmwareArtifact modified = artifact("ota_0", EspExecutableRole.OTA,
            0x210000, digest('b'), "2.1.0", 4, EspImageHashState.VERIFIED);
        EspFactoryOtaAnalyzer analyzer = new EspFactoryOtaAnalyzer();

        assertEquals(EspArtifactChangeKind.UNCHANGED,
            analyze(analyzer, Optional.of(factory), Optional.of(same)).diff().kind());
        assertEquals(EspArtifactChangeKind.MOVED,
            analyze(analyzer, Optional.of(factory), Optional.of(moved)).diff().kind());
        assertEquals(EspArtifactChangeKind.MODIFIED,
            analyze(analyzer, Optional.of(factory), Optional.of(modified)).diff().kind());
        assertEquals(EspArtifactChangeKind.ADDED,
            analyze(analyzer, Optional.empty(), Optional.of(modified)).diff().kind());
        assertEquals(EspArtifactChangeKind.REMOVED,
            analyze(analyzer, Optional.of(factory), Optional.empty()).diff().kind());
    }

    @Test
    void emitsEvidenceBoundedEspFindingsAndRedactsSensitivePartitionContent()
            throws Exception {
        EspFirmwareArtifact factory = artifact("factory", EspExecutableRole.FACTORY,
            0x10000, digest('a'), "2.0.0", 5, EspImageHashState.VERIFIED);
        EspFirmwareArtifact ota = artifact("ota_0", EspExecutableRole.OTA,
            0x210000, digest('b'), "1.0.0", 2, EspImageHashState.INVALID);
        EspPartitionEntry nvsKeys = partition("nvs_keys", 1, 4, 0x9000, 0);
        EspPartitionEntry formerlyEncrypted = partition("storage", 1, 0x82,
            0x300000, 0);

        EspFactoryOtaReport report = new EspFactoryOtaAnalyzer().analyze(
            new EspFactoryOtaContext(Optional.of(factory), Optional.of(ota),
                List.of(nvsKeys, formerlyEncrypted)), ParserLimits.defaults(),
            CancellationToken.none());

        assertEquals(EspArtifactChangeKind.MODIFIED, report.diff().kind());
        assertEquals(List.of("ESP_INVALID_IMAGE_HASH", "ESP_NVS_KEYS_PLAINTEXT",
            "ESP_SECURE_VERSION_ROLLBACK"),
            report.findings().stream().map(EspCtfFinding::code).toList());
        EspCtfFinding rollback = report.findings().stream()
            .filter(finding -> finding.code().equals("ESP_SECURE_VERSION_ROLLBACK"))
            .findFirst().orElseThrow();
        assertEquals(Confidence.VERIFIED, rollback.confidence());
        assertFalse(rollback.secret());
        assertTrue(report.findings().stream().noneMatch(
            finding -> finding.explanation().contains("key bytes")));
        assertEquals(List.of("esp-factory-ota-diff", "esp-image-hash-regression",
            "esp-nvs-key-partition", "esp-secure-version-regression"),
            report.detectorsRun());
        assertThrows(UnsupportedOperationException.class, () -> report.findings().clear());
    }

    @Test
    void avoidsVersionStringGuessingAndEnforcesLimitsCancellationAndImmutability()
            throws Exception {
        EspFirmwareArtifact factory = new EspFirmwareArtifact("factory",
            EspExecutableRole.FACTORY, Optional.of("factory"),
            new EspFlashRange(0x10000, 0x1000), digest('a'),
            Optional.of("release-new"), OptionalLong.empty(),
            EspImageHashState.VERIFIED);
        EspFirmwareArtifact ota = new EspFirmwareArtifact("ota_0",
            EspExecutableRole.OTA, Optional.of("ota_0"),
            new EspFlashRange(0x210000, 0x1000), digest('b'),
            Optional.of("release-old"), OptionalLong.empty(),
            EspImageHashState.VERIFIED);
        EspFactoryOtaContext context = new EspFactoryOtaContext(Optional.of(factory),
            Optional.of(ota), List.of());

        EspFactoryOtaReport report = new EspFactoryOtaAnalyzer().analyze(context,
            ParserLimits.defaults(), CancellationToken.none());
        assertTrue(report.findings().stream().noneMatch(
            finding -> finding.code().contains("ROLLBACK")));
        assertThrows(UnsupportedOperationException.class,
            () -> context.partitions().clear());

        ParserLimits tiny = new ParserLimits(8, 8, 8, 1, 8,
            Duration.ofSeconds(30));
        DiagnosticException limited = assertThrows(DiagnosticException.class,
            () -> new EspFactoryOtaAnalyzer().analyze(context, tiny,
                CancellationToken.none()));
        assertEquals(DiagnosticCode.LIMIT_EXCEEDED, limited.diagnostic().code());

        CancellationSource cancellation = new CancellationSource();
        cancellation.cancel();
        DiagnosticException cancelled = assertThrows(DiagnosticException.class,
            () -> new EspFactoryOtaAnalyzer().analyze(context,
                ParserLimits.defaults(), cancellation.token()));
        assertEquals(DiagnosticCode.CANCELLED, cancelled.diagnostic().code());
    }

    private static EspFactoryOtaReport analyze(EspFactoryOtaAnalyzer analyzer,
            Optional<EspFirmwareArtifact> factory, Optional<EspFirmwareArtifact> ota)
            throws Exception {
        return analyzer.analyze(new EspFactoryOtaContext(factory, ota, List.of()),
            ParserLimits.defaults(), CancellationToken.none());
    }

    private static EspFirmwareArtifact artifact(String id, EspExecutableRole role,
            long offset, String digest, String version, long secureVersion,
            EspImageHashState hashState) {
        return new EspFirmwareArtifact(id, role, Optional.of(id),
            new EspFlashRange(offset, 0x1000), digest, Optional.of(version),
            OptionalLong.of(secureVersion), hashState);
    }

    private static EspPartitionEntry partition(String label, int type, int subtype,
            long offset, long flags) {
        return new EspPartitionEntry(0, label, type, subtype,
            new EspFlashRange(offset, 0x1000), flags, new SourceRange(0x8000, 32));
    }

    private static String digest(char value) {
        return String.valueOf(value).repeat(64);
    }
}
