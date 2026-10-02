package io.github.rezabakhshi.embedra.analyzers.stm32;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.analyzers.esp.EspArtifactChangeKind;
import io.github.rezabakhshi.embedra.core.CancellationSource;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.core.model.Evidence;
import io.github.rezabakhshi.embedra.core.model.EvidenceKind;
import io.github.rezabakhshi.embedra.core.stm32.input.Stm32PartSelection;
import io.github.rezabakhshi.embedra.targets.stm32.catalog.Stm32CuratedPartIds;
import io.github.rezabakhshi.embedra.targets.stm32.vector.Stm32VectorPlanner;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class Stm32FirmwareDiffAnalyzerTest {
    private static final String PART = "STM32F103C8T6";

    private static final String OTHER_PART = "STM32F103CBT6";

    private static final String DIGEST_A = "a".repeat(64);

    private static final String DIGEST_B = "b".repeat(64);

    private static final Stm32PartSelection SELECTION =
        part -> PART.equals(part) || OTHER_PART.equals(part);

    private static final Stm32FirmwareDiffAnalyzer ANALYZER = new Stm32FirmwareDiffAnalyzer();

    @Test
    void classifiesUnchangedMovedModifiedAddedAndRemovedViews() throws Exception {
        Stm32FirmwareArtifact baseline =
            artifact(PART, "build-1", Stm32FirmwareRole.BASELINE, 0x08000000L, DIGEST_A);
        Stm32FirmwareArtifact identical =
            artifact(PART, "build-2", Stm32FirmwareRole.CANDIDATE, 0x08000000L, DIGEST_A);
        Stm32FirmwareArtifact moved =
            artifact(PART, "build-2", Stm32FirmwareRole.CANDIDATE, 0x08010000L, DIGEST_A);
        Stm32FirmwareArtifact modified =
            artifact(PART, "build-2", Stm32FirmwareRole.CANDIDATE, 0x08010000L, DIGEST_B);

        assertEquals(EspArtifactChangeKind.UNCHANGED,
            diff(baseline, Optional.of(identical)).diff().kind());
        assertEquals(EspArtifactChangeKind.MOVED,
            diff(baseline, Optional.of(moved)).diff().kind());
        assertEquals(EspArtifactChangeKind.MODIFIED,
            diff(baseline, Optional.of(modified)).diff().kind());
        assertEquals(EspArtifactChangeKind.ADDED,
            diff(null, Optional.of(modified)).diff().kind());
        assertEquals(EspArtifactChangeKind.REMOVED,
            diff(baseline, Optional.empty()).diff().kind());
    }

    @Test
    void comparesDigestsBeforeImageExtentsLikeTheSharedT025Contract() throws Exception {
        Stm32FirmwareArtifact baseline =
            artifact(PART, "build-1", Stm32FirmwareRole.BASELINE, 0x08000000L, DIGEST_A);
        Stm32FirmwareArtifact modifiedInPlace =
            artifact(PART, "build-2", Stm32FirmwareRole.CANDIDATE, 0x08000000L, DIGEST_B);
        Stm32FirmwareArtifact modifiedAndMoved =
            artifact(PART, "build-2", Stm32FirmwareRole.CANDIDATE, 0x08020000L, DIGEST_B);

        assertEquals(EspArtifactChangeKind.MODIFIED,
            diff(baseline, Optional.of(modifiedInPlace)).diff().kind());
        assertEquals(EspArtifactChangeKind.MODIFIED,
            diff(baseline, Optional.of(modifiedAndMoved)).diff().kind());
    }

    @Test
    void differingArtifactIdsDoNotAlterTheClassification() throws Exception {
        Stm32FirmwareArtifact baseline =
            artifact(PART, "factory-build", Stm32FirmwareRole.BASELINE, 0x08000000L, DIGEST_A);
        Stm32FirmwareArtifact renamed = artifact(PART, "renamed-candidate",
            Stm32FirmwareRole.CANDIDATE, 0x08000000L, DIGEST_A);

        assertEquals(EspArtifactChangeKind.UNCHANGED,
            diff(baseline, Optional.of(renamed)).diff().kind());
    }

    @Test
    void reportsProvenanceBearingEvidenceAndRunsTheDiffDetector() throws Exception {
        Stm32FirmwareArtifact baseline =
            artifact(PART, "build-1", Stm32FirmwareRole.BASELINE, 0x08000000L, DIGEST_A);
        Stm32FirmwareArtifact moved =
            artifact(PART, "build-2", Stm32FirmwareRole.CANDIDATE, 0x08010000L, DIGEST_A);

        Stm32FirmwareDiffReport report = diff(baseline, Optional.of(moved));
        assertEquals(List.of("stm32-firmware-diff"), report.detectorsRun());
        assertTrue(report.diff().evidence().stream()
            .anyMatch(entry -> entry.kind() == EvidenceKind.VERIFIED_CHECKSUM
                && entry.detail().contains("build-1") && entry.detail().contains("build-2")
                && entry.detail().contains(PART)));
        assertTrue(report.diff().evidence().stream()
            .anyMatch(entry -> baseline.evidence().get(0).equals(entry)));
    }

    @Test
    void repeatedAnalysisIsDeterministicAndResultsAreImmutable() throws Exception {
        Stm32FirmwareArtifact baseline =
            artifact(PART, "build-1", Stm32FirmwareRole.BASELINE, 0x08000000L, DIGEST_A);
        Stm32FirmwareArtifact moved =
            artifact(PART, "build-2", Stm32FirmwareRole.CANDIDATE, 0x08010000L, DIGEST_A);

        Stm32FirmwareDiffReport first = diff(baseline, Optional.of(moved));
        assertEquals(first, diff(baseline, Optional.of(moved)));
        assertNotEquals(first, diff(baseline, Optional.of(artifact(PART, "build-3",
            Stm32FirmwareRole.CANDIDATE, 0x08000000L, DIGEST_A))));
        assertThrows(UnsupportedOperationException.class,
            () -> first.diff().evidence().clear());
        assertThrows(UnsupportedOperationException.class,
            () -> first.detectorsRun().clear());
        assertThrows(UnsupportedOperationException.class,
            () -> baseline.evidence().clear());
    }

    @Test
    void bindingArtifactsOfDifferentExactPartsFailsClosed() {
        Stm32FirmwareArtifact baseline =
            artifact(PART, "build-1", Stm32FirmwareRole.BASELINE, 0x08000000L, DIGEST_A);
        Stm32FirmwareArtifact candidate =
            artifact(OTHER_PART, "build-2", Stm32FirmwareRole.CANDIDATE, 0x08010000L, DIGEST_B);

        Stm32FirmwareDiffAnalyzer.DiffException exception = assertThrows(
            Stm32FirmwareDiffAnalyzer.DiffException.class,
            () -> ANALYZER.analyze(new Stm32FirmwareDiffContext(SELECTION,
                Optional.of(baseline), Optional.of(candidate)), ParserLimits.defaults(),
                CancellationToken.none()));
        assertEquals(Stm32FirmwareDiffAnalyzer.Diagnostic.DIFF_EXACT_PART_MISMATCH,
            exception.diagnostic());
        assertTrue(exception.getMessage().contains(PART));
        assertTrue(exception.getMessage().contains(OTHER_PART));
    }

    @Test
    void bindsArtifactsToTheDigestPinnedCuratedSelectionOnly() throws Exception {
        Stm32CuratedPartIds pinned = Stm32CuratedPartIds.load(
            Path.of("catalogs/stm32/2026-09-29/selection.json"), ParserLimits.defaults(),
            CancellationToken.none());
        assertTrue(pinned.containsExactPart(PART));

        Stm32FirmwareArtifact candidate = artifact(PART, "added-candidate",
            Stm32FirmwareRole.CANDIDATE, 0x08000000L, DIGEST_A);
        assertEquals(EspArtifactChangeKind.ADDED, ANALYZER.analyze(new Stm32FirmwareDiffContext(
            pinned, Optional.empty(), Optional.of(candidate)), ParserLimits.defaults(),
            CancellationToken.none()).diff().kind());

        Stm32FirmwareDiffAnalyzer.DiffException exception = assertThrows(
            Stm32FirmwareDiffAnalyzer.DiffException.class,
            () -> ANALYZER.analyze(new Stm32FirmwareDiffContext(pinned,
                Optional.of(artifact("STM32F103C8", "uncurated",
                    Stm32FirmwareRole.BASELINE, 0x08000000L, DIGEST_A)), Optional.empty()),
                ParserLimits.defaults(), CancellationToken.none()));
        assertEquals(Stm32FirmwareDiffAnalyzer.Diagnostic.DIFF_EXACT_PART_UNCURATED,
            exception.diagnostic());
    }

    @Test
    void rejectsAmbiguousOrMalformedDiffContexts() {
        Stm32FirmwareArtifact baseline =
            artifact(PART, "build-1", Stm32FirmwareRole.BASELINE, 0x08000000L, DIGEST_A);
        Stm32FirmwareArtifact candidate =
            artifact(PART, "build-2", Stm32FirmwareRole.CANDIDATE, 0x08000000L, DIGEST_A);

        assertThrows(IllegalArgumentException.class,
            () -> new Stm32FirmwareDiffContext(SELECTION, Optional.empty(), Optional.empty()));
        assertThrows(IllegalArgumentException.class,
            () -> new Stm32FirmwareDiffContext(SELECTION, Optional.of(candidate),
                Optional.empty()));
        assertThrows(IllegalArgumentException.class,
            () -> new Stm32FirmwareDiffContext(SELECTION, Optional.empty(),
                Optional.of(baseline)));
    }

    @Test
    void rejectsMalformedArtifactsBeforeAnyComparison() {
        assertThrows(IllegalArgumentException.class, () -> artifact(PART, "truncated-digest",
            Stm32FirmwareRole.BASELINE, 0x08000000L, "a".repeat(63)));
        assertThrows(IllegalArgumentException.class, () -> artifact(PART, "uppercase-digest",
            Stm32FirmwareRole.BASELINE, 0x08000000L, "A".repeat(64)));
        assertThrows(IllegalArgumentException.class, () -> artifact(" ", "blank-part",
            Stm32FirmwareRole.BASELINE, 0x08000000L, DIGEST_A));
        assertThrows(IllegalArgumentException.class, () -> artifact(PART, " ",
            Stm32FirmwareRole.BASELINE, 0x08000000L, DIGEST_A));
        assertThrows(IllegalArgumentException.class, () -> new Stm32FirmwareArtifact(PART,
            "empty-range", Stm32FirmwareRole.BASELINE,
            new Stm32VectorPlanner.ImageRange(0x08000000L, 0), DIGEST_A,
            List.of(new Evidence(EvidenceKind.VERIFIED_CHECKSUM, "test", "detail"))));
        assertThrows(IllegalArgumentException.class, () -> new Stm32FirmwareArtifact(PART,
            "no-provenance", Stm32FirmwareRole.BASELINE,
            new Stm32VectorPlanner.ImageRange(0x08000000L, 0x1000), DIGEST_A, List.of()));
    }

    @Test
    void enforcesSharedLimitsAndCancellation() {
        Stm32FirmwareArtifact baseline =
            artifact(PART, "build-1", Stm32FirmwareRole.BASELINE, 0x08000000L, DIGEST_A);
        Stm32FirmwareArtifact candidate =
            artifact(PART, "build-2", Stm32FirmwareRole.CANDIDATE, 0x08010000L, DIGEST_B);
        Stm32FirmwareDiffContext context = new Stm32FirmwareDiffContext(SELECTION,
            Optional.of(baseline), Optional.of(candidate));

        ParserLimits tiny = new ParserLimits(8, 8, 8, 1, 8, Duration.ofSeconds(30));
        DiagnosticException limited = assertThrows(DiagnosticException.class,
            () -> ANALYZER.analyze(context, tiny, CancellationToken.none()));
        assertEquals(DiagnosticCode.LIMIT_EXCEEDED, limited.diagnostic().code());

        CancellationSource cancellation = new CancellationSource();
        cancellation.cancel();
        DiagnosticException cancelled = assertThrows(DiagnosticException.class,
            () -> ANALYZER.analyze(context, ParserLimits.defaults(), cancellation.token()));
        assertEquals(DiagnosticCode.CANCELLED, cancelled.diagnostic().code());
    }

    private static Stm32FirmwareDiffReport diff(Stm32FirmwareArtifact baseline,
            Optional<Stm32FirmwareArtifact> candidate) throws Exception {
        return ANALYZER.analyze(new Stm32FirmwareDiffContext(SELECTION,
            Optional.ofNullable(baseline), candidate), ParserLimits.defaults(),
            CancellationToken.none());
    }

    private static Stm32FirmwareArtifact artifact(String part, String id,
            Stm32FirmwareRole role, long base, String digest) {
        return new Stm32FirmwareArtifact(part, id, role,
            new Stm32VectorPlanner.ImageRange(base, 0x1000), digest,
            List.of(new Evidence(EvidenceKind.VERIFIED_CHECKSUM, "validated import",
                "Confirmed " + role + " image extent and content digest")));
    }
}
