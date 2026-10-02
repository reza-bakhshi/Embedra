package io.github.rezabakhshi.embedra.analyzers.stm32;

import static io.github.rezabakhshi.embedra.analyzers.stm32.Stm32SignatureTestSupport.COMPILER;
import static io.github.rezabakhshi.embedra.analyzers.stm32.Stm32SignatureTestSupport.OPTIMIZATION;
import static io.github.rezabakhshi.embedra.analyzers.stm32.Stm32SignatureTestSupport.allSpecifiedMask;
import static io.github.rezabakhshi.embedra.analyzers.stm32.Stm32SignatureTestSupport.pack;
import static io.github.rezabakhshi.embedra.analyzers.stm32.Stm32SignatureTestSupport.signature;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.CancellationSource;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.core.model.Confidence;
import io.github.rezabakhshi.embedra.core.model.Evidence;
import io.github.rezabakhshi.embedra.core.model.EvidenceKind;
import io.github.rezabakhshi.embedra.core.stm32.input.Stm32PartSelection;
import io.github.rezabakhshi.embedra.targets.stm32.catalog.Stm32CuratedPartIds;
import io.github.rezabakhshi.embedra.targets.stm32.security.Stm32SecurityCatalog;
import io.github.rezabakhshi.embedra.targets.stm32.security.Stm32SecurityRecord;
import io.github.rezabakhshi.embedra.targets.stm32.vector.Stm32VectorPlanner;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.OptionalLong;
import org.junit.jupiter.api.Test;

class Stm32CtfEnrichmentAnalyzerTest {
    private static final String PART = "STM32F103C8T6";

    private static final String OTHER_PART = "STM32F103CBT6";

    private static final byte[] PATTERN =
        {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte) 0x88};

    private static final Stm32PartSelection SELECTION =
        part -> PART.equals(part) || OTHER_PART.equals(part);

    private static final Path SECURITY_SNAPSHOT =
        Path.of("catalogs/stm32/2026-09-29/security-domains.json");

    private static final Path CURATED_SELECTION =
        Path.of("catalogs/stm32/2026-09-29/selection.json");

    private static final Stm32CtfEnrichmentAnalyzer ANALYZER = new Stm32CtfEnrichmentAnalyzer();

    @Test
    void signatureMatchesBecomeRankedProvenanceBearingLeads() throws Exception {
        Stm32SignaturePack signaturePack = pack(signature("stm32f1.hal.HAL_Init.Os",
            "HAL_Init", PATTERN, allSpecifiedMask(PATTERN.length)));
        Stm32CtfEnrichmentContext context = context(List.of(
            new Stm32FunctionBytes(0x08000100L, PATTERN),
            new Stm32FunctionBytes(0x08000200L, new byte[8])));

        Stm32CtfEnrichmentReport report = ANALYZER.analyze(context, signaturePack,
            ParserLimits.defaults(), CancellationToken.none());

        assertEquals(1, report.leads().size());
        Stm32CtfLead lead = report.leads().get(0);
        assertEquals("STM32_SIGNATURE_LIBRARY_FUNCTION", lead.code());
        assertEquals(Stm32CtfLead.Severity.LOW, lead.severity());
        assertEquals(OptionalLong.of(0x08000100L), lead.address());
        assertEquals(Confidence.VERIFIED, lead.confidence());
        assertEquals(EvidenceKind.EXACT_SIGNATURE_MATCH, lead.evidence().get(0).kind());
        assertTrue(lead.explanation().contains("HAL_Init"));
        assertTrue(lead.explanation().contains("identification lead"));
        assertTrue(lead.explanation().contains(PART));
        assertEquals(Stm32SecurityEvidence.Status.NOT_SUPPLIED,
            report.securityEvidence().status());
        assertTrue(report.detectorsRun().contains("stm32-signature-match"));
        assertTrue(report.unsupportedCapabilities().contains("stm32-logging-assert-recovery"));
    }

    @Test
    void enrichedSignatureLeadsEqualTheSharedT043MatcherVerbatim() throws Exception {
        Stm32SignaturePack signaturePack = pack(signature("stm32f1.hal.HAL_Init.Os",
            "HAL_Init", PATTERN, allSpecifiedMask(PATTERN.length)));
        List<Stm32FunctionBytes> functions = List.of(
            new Stm32FunctionBytes(0x08000100L, PATTERN),
            new Stm32FunctionBytes(0x08000200L, new byte[8]));
        Stm32CtfEnrichmentContext context = context(functions);

        Stm32CtfEnrichmentReport report = ANALYZER.analyze(context, signaturePack,
            ParserLimits.defaults(), CancellationToken.none());

        Stm32SignatureMatchReport shared = Stm32SignatureMatcher.match(
            new Stm32SignatureContext(PART, "STM32F1", Optional.of(COMPILER),
                Optional.of(OPTIMIZATION), functions), signaturePack, ParserLimits.defaults(),
            CancellationToken.none());
        assertEquals(shared, report.signatureReport());
        assertEquals(shared.matches().size(), report.leads().stream()
            .filter(lead -> lead.code().equals("STM32_SIGNATURE_LIBRARY_FUNCTION")).count());
    }

    @Test
    void maskedSignatureMatchesStayDerivedLeads() throws Exception {
        byte[] mask = allSpecifiedMask(PATTERN.length);
        mask[3] = 0;
        Stm32SignaturePack signaturePack = pack(signature("stm32f1.hal.HAL_Init.Os",
            "HAL_Init", PATTERN, mask));
        Stm32CtfEnrichmentContext context = context(List.of(
            new Stm32FunctionBytes(0x08000100L,
                new byte[] {0x11, 0x22, 0x33, (byte) 0xAA, 0x55, 0x66, 0x77, (byte) 0x88})));

        Stm32CtfEnrichmentReport report = ANALYZER.analyze(context, signaturePack,
            ParserLimits.defaults(), CancellationToken.none());

        assertEquals(1, report.leads().size());
        assertEquals(Confidence.DERIVED, report.leads().get(0).confidence());
        assertEquals(EvidenceKind.DERIVED_RULE, report.leads().get(0).evidence().get(0).kind());
    }

    @Test
    void missingBuildEvidenceIsAnExplicitGapNeverAnInventedLead() throws Exception {
        Stm32SignaturePack signaturePack = pack(signature("stm32f1.hal.HAL_Init.Os",
            "HAL_Init", PATTERN, allSpecifiedMask(PATTERN.length)));
        Stm32CtfEnrichmentContext context = new Stm32CtfEnrichmentContext(SELECTION,
            List.of(artifact(PART, "build-1", 0x08000000L)),
            List.of(new Stm32FunctionBytes(0x08000100L, PATTERN)),
            Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty());

        Stm32CtfEnrichmentReport report = ANALYZER.analyze(context, signaturePack,
            ParserLimits.defaults(), CancellationToken.none());

        assertTrue(report.leads().isEmpty());
        assertEquals(Stm32SignatureNonMatch.Kind.EVIDENCE_MISSING,
            report.signatureReport().nonMatches().get(0).kind());
        assertTrue(report.unsupportedCapabilities().contains("signature-evidence-missing"));
    }

    @Test
    void unavailableSignatureIndexIsAnExplicitGapNeverAnInventedLead() throws Exception {
        Stm32LibrarySignature otherOptimization = new Stm32LibrarySignature(
            "stm32f1.hal.HAL_Init.O2", "stm32f1xx-hal", "stm32f1xx-hal", "HAL_Init",
            "STM32F1", COMPILER, "-O2",
            "Drivers/STM32F1xx_HAL_Driver/Src/stm32f1xx_hal.c",
            Stm32SignatureTestSupport.SOURCE_SHA, PATTERN, allSpecifiedMask(PATTERN.length));
        Stm32CtfEnrichmentContext context = context(List.of(
            new Stm32FunctionBytes(0x08000100L, PATTERN)));

        Stm32CtfEnrichmentReport report = ANALYZER.analyze(context, pack(otherOptimization),
            ParserLimits.defaults(), CancellationToken.none());

        assertTrue(report.leads().isEmpty());
        assertEquals(Stm32SignatureNonMatch.Kind.INDEX_UNAVAILABLE,
            report.signatureReport().nonMatches().get(0).kind());
        assertTrue(report.unsupportedCapabilities().contains("signature-index-unavailable"));
    }

    @Test
    void classifiesPinnedSecurityEvidenceAndEmitsImageRangeLeads() throws Exception {
        Stm32CuratedPartIds selection = Stm32CuratedPartIds.load(CURATED_SELECTION,
            ParserLimits.defaults(), CancellationToken.none());
        Stm32SecurityRecord record = Stm32SecurityCatalog.load(SECURITY_SNAPSHOT, selection,
            ParserLimits.defaults(), CancellationToken.none()).requireRecord("STM32L552ZET6Q");
        Stm32CtfEnrichmentContext context = new Stm32CtfEnrichmentContext(selection,
            List.of(artifact("STM32L552ZET6Q", "build-1", 0x0C000000L)), List.of(),
            Optional.empty(), Optional.empty(), Optional.empty(), Optional.of(record));

        Stm32CtfEnrichmentReport report = ANALYZER.analyze(context,
            pack(signature("stm32f1.hal.HAL_Init.Os", "HAL_Init", PATTERN,
                allSpecifiedMask(PATTERN.length))), ParserLimits.defaults(),
            CancellationToken.none());

        assertEquals(Stm32SecurityEvidence.Status.PINNED, report.securityEvidence().status());
        assertEquals(List.of("FLASH_S", "SRAM1_S", "SRAM2_S"),
            report.securityEvidence().pinnedWindowIds());
        assertEquals(1, report.leads().size());
        Stm32CtfLead lead = report.leads().get(0);
        assertEquals("STM32_IMAGE_IN_SECURE_ALIAS", lead.code());
        assertEquals(Stm32CtfLead.Severity.MEDIUM, lead.severity());
        assertEquals(OptionalLong.of(0x0C000000L), lead.address());
        assertTrue(lead.explanation().contains("FLASH_S"));
        assertTrue(lead.explanation().contains("stm32l552xx.h"));
        assertTrue(lead.evidence().stream().anyMatch(entry ->
            entry.kind() == EvidenceKind.DOCUMENTED_FIELD));
        assertTrue(report.detectorsRun().contains("stm32-security-evidence"));
    }

    @Test
    void plainFlashImagesProduceNoSecurityLead() throws Exception {
        Stm32CuratedPartIds selection = Stm32CuratedPartIds.load(CURATED_SELECTION,
            ParserLimits.defaults(), CancellationToken.none());
        Stm32SecurityRecord record = Stm32SecurityCatalog.load(SECURITY_SNAPSHOT, selection,
            ParserLimits.defaults(), CancellationToken.none()).requireRecord("STM32L552ZET6Q");
        Stm32CtfEnrichmentContext context = new Stm32CtfEnrichmentContext(selection,
            List.of(artifact("STM32L552ZET6Q", "build-1", 0x08000000L)), List.of(),
            Optional.empty(), Optional.empty(), Optional.empty(), Optional.of(record));

        Stm32CtfEnrichmentReport report = ANALYZER.analyze(context,
            pack(signature("stm32f1.hal.HAL_Init.Os", "HAL_Init", PATTERN,
                allSpecifiedMask(PATTERN.length))), ParserLimits.defaults(),
            CancellationToken.none());

        assertTrue(report.leads().isEmpty());
        assertEquals(Stm32SecurityEvidence.Status.PINNED, report.securityEvidence().status());
    }

    @Test
    void unpinnedSecurityRecordsStayExplicitlyUnavailable() throws Exception {
        Stm32CuratedPartIds selection = Stm32CuratedPartIds.load(CURATED_SELECTION,
            ParserLimits.defaults(), CancellationToken.none());
        Stm32SecurityRecord record = Stm32SecurityCatalog.load(SECURITY_SNAPSHOT, selection,
            ParserLimits.defaults(), CancellationToken.none()).requireRecord("STM32H503RBT6");
        Stm32CtfEnrichmentContext context = new Stm32CtfEnrichmentContext(selection,
            List.of(artifact("STM32H503RBT6", "build-1", 0x08000000L)), List.of(),
            Optional.empty(), Optional.empty(), Optional.empty(), Optional.of(record));

        Stm32CtfEnrichmentReport report = ANALYZER.analyze(context,
            pack(signature("stm32f1.hal.HAL_Init.Os", "HAL_Init", PATTERN,
                allSpecifiedMask(PATTERN.length))), ParserLimits.defaults(),
            CancellationToken.none());

        assertEquals(Stm32SecurityEvidence.Status.UNAVAILABLE,
            report.securityEvidence().status());
        assertEquals("NON_SECURE_SUFFIXED_ALIASES_ONLY", report.securityEvidence().reason());
        assertTrue(report.securityEvidence().pinnedWindowIds().isEmpty());
        assertTrue(report.leads().isEmpty());
    }

    @Test
    void sweepsEveryCuratedPartWithoutPromotingAnySupportState() throws Exception {
        Stm32CuratedPartIds selection = Stm32CuratedPartIds.load(CURATED_SELECTION,
            ParserLimits.defaults(), CancellationToken.none());
        Stm32SecurityCatalog catalog = Stm32SecurityCatalog.load(SECURITY_SNAPSHOT, selection,
            ParserLimits.defaults(), CancellationToken.none());
        int pinned = 0;
        int unavailable = 0;
        for (Stm32SecurityRecord record : catalog.records()) {
            Stm32CtfEnrichmentContext context = new Stm32CtfEnrichmentContext(selection,
                List.of(artifact(record.exactPart(), "build-1", 0x08000000L)), List.of(),
                Optional.of("STM32F1"), Optional.of(COMPILER), Optional.of(OPTIMIZATION),
                Optional.of(record));
            Stm32CtfEnrichmentReport report = ANALYZER.analyze(context,
                pack(signature("stm32f1.hal.HAL_Init.Os", "HAL_Init", PATTERN,
                    allSpecifiedMask(PATTERN.length))), ParserLimits.defaults(),
                CancellationToken.none());
            if (report.securityEvidence().status() == Stm32SecurityEvidence.Status.PINNED) {
                pinned++;
                assertTrue(!report.securityEvidence().pinnedWindowIds().isEmpty());
            }
            else {
                unavailable++;
                assertTrue(report.securityEvidence().reason() != null
                    && !report.securityEvidence().reason().isBlank());
                assertTrue(report.securityEvidence().pinnedWindowIds().isEmpty());
            }
            assertTrue(report.leads().stream().noneMatch(lead ->
                lead.code().equals("STM32_IMAGE_IN_SECURE_ALIAS")));
            assertTrue(report.signatureReport().matches().isEmpty());
        }
        assertEquals(19, pinned);
        assertEquals(34, unavailable);
    }

    @Test
    void partBindingFailsClosedOnSecurityRecordOrArtifactDisagreement() throws Exception {
        Stm32CuratedPartIds selection = Stm32CuratedPartIds.load(CURATED_SELECTION,
            ParserLimits.defaults(), CancellationToken.none());
        Stm32SecurityRecord record = Stm32SecurityCatalog.load(SECURITY_SNAPSHOT, selection,
            ParserLimits.defaults(), CancellationToken.none()).requireRecord("STM32H503RBT6");

        Stm32CtfEnrichmentAnalyzer.EnrichmentException security = assertThrows(
            Stm32CtfEnrichmentAnalyzer.EnrichmentException.class,
            () -> ANALYZER.analyze(new Stm32CtfEnrichmentContext(SELECTION,
                List.of(artifact(PART, "build-1", 0x08000000L)), List.of(),
                Optional.empty(), Optional.empty(), Optional.empty(), Optional.of(record)),
                pack(signature("stm32f1.hal.HAL_Init.Os", "HAL_Init", PATTERN,
                    allSpecifiedMask(PATTERN.length))), ParserLimits.defaults(),
                CancellationToken.none()));
        assertEquals(Stm32CtfEnrichmentAnalyzer.Diagnostic.ENRICHMENT_SECURITY_PART_MISMATCH,
            security.diagnostic());

        Stm32CtfEnrichmentAnalyzer.EnrichmentException artifacts = assertThrows(
            Stm32CtfEnrichmentAnalyzer.EnrichmentException.class,
            () -> ANALYZER.analyze(new Stm32CtfEnrichmentContext(SELECTION,
                List.of(artifact(PART, "build-1", 0x08000000L),
                    new Stm32FirmwareArtifact(OTHER_PART, "build-2",
                        Stm32FirmwareRole.BASELINE,
                        new Stm32VectorPlanner.ImageRange(0x08010000L, 0x1000), "b".repeat(64),
                        List.of(new Evidence(EvidenceKind.VERIFIED_CHECKSUM,
                            "validated import", "Confirmed image extent")))), List.of(),
                Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty()),
                pack(signature("stm32f1.hal.HAL_Init.Os", "HAL_Init", PATTERN,
                    allSpecifiedMask(PATTERN.length))), ParserLimits.defaults(),
                CancellationToken.none()));
        assertEquals(
            Stm32CtfEnrichmentAnalyzer.Diagnostic.ENRICHMENT_ARTIFACT_PART_MISMATCH,
            artifacts.diagnostic());
    }

    @Test
    void uncuratedExactPartsFailClosed() throws Exception {
        Stm32CtfEnrichmentContext context = context(List.of(
            new Stm32FunctionBytes(0x08000100L, PATTERN)), "STM32F103C8");
        Stm32CtfEnrichmentAnalyzer.EnrichmentException exception = assertThrows(
            Stm32CtfEnrichmentAnalyzer.EnrichmentException.class,
            () -> ANALYZER.analyze(context, pack(signature("stm32f1.hal.HAL_Init.Os",
                "HAL_Init", PATTERN, allSpecifiedMask(PATTERN.length))),
                ParserLimits.defaults(), CancellationToken.none()));
        assertEquals(Stm32CtfEnrichmentAnalyzer.Diagnostic.ENRICHMENT_PART_UNCURATED,
            exception.diagnostic());
    }

    @Test
    void curatedExactPartsEnrichWithoutUncuratedFailure() throws Exception {
        Stm32CuratedPartIds pinned = Stm32CuratedPartIds.load(CURATED_SELECTION,
            ParserLimits.defaults(), CancellationToken.none());
        Stm32CtfEnrichmentContext context = new Stm32CtfEnrichmentContext(pinned,
            List.of(artifact("STM32L552ZET6Q", "build-1", 0x08000000L)), List.of(),
            Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty());
        Stm32CtfEnrichmentReport report = ANALYZER.analyze(context,
            pack(signature("stm32f1.hal.HAL_Init.Os", "HAL_Init", PATTERN,
                allSpecifiedMask(PATTERN.length))), ParserLimits.defaults(),
            CancellationToken.none());
        assertTrue(report.leads().isEmpty());
        assertEquals(Stm32SecurityEvidence.Status.NOT_SUPPLIED,
            report.securityEvidence().status());
    }

    @Test
    void rejectsDuplicateAmbiguousAndOutOfRangeCandidateRecords() {
        assertThrows(IllegalArgumentException.class, () -> context(List.of(
            new Stm32FunctionBytes(0x08000100L, PATTERN),
            new Stm32FunctionBytes(0x08000100L, new byte[8]))));
        assertThrows(IllegalArgumentException.class, () -> new Stm32CtfEnrichmentContext(
            SELECTION, List.of(artifact(PART, "build-1", 0x08000000L),
                artifact(PART, "build-1", 0x08010000L)), List.of(),
            Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty()));
        assertThrows(IllegalArgumentException.class, () -> new Stm32CtfEnrichmentContext(
            SELECTION, List.of(artifact(PART, "build-1", 0x08000000L),
                artifact(PART, "build-2", 0x08010000L)), List.of(),
            Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty()));
        assertThrows(IllegalArgumentException.class,
            () -> context(List.of(new Stm32FunctionBytes(0x1_0000_0000L, PATTERN))));
    }

    @Test
    void enforcesSharedLimitsAndCancellation() throws Exception {
        Stm32CtfEnrichmentContext context = context(List.of(
            new Stm32FunctionBytes(0x08000100L, PATTERN)));

        ParserLimits tiny = new ParserLimits(1024, 1024, 1024, 1, 8, Duration.ofSeconds(30));
        DiagnosticException limited = assertThrows(DiagnosticException.class,
            () -> ANALYZER.analyze(context, pack(signature("stm32f1.hal.HAL_Init.Os",
                "HAL_Init", PATTERN, allSpecifiedMask(PATTERN.length))), tiny,
                CancellationToken.none()));
        assertEquals(DiagnosticCode.LIMIT_EXCEEDED, limited.diagnostic().code());

        CancellationSource cancellation = new CancellationSource();
        cancellation.cancel();
        DiagnosticException cancelled = assertThrows(DiagnosticException.class,
            () -> ANALYZER.analyze(context, pack(signature("stm32f1.hal.HAL_Init.Os",
                "HAL_Init", PATTERN, allSpecifiedMask(PATTERN.length))),
                ParserLimits.defaults(), cancellation.token()));
        assertEquals(DiagnosticCode.CANCELLED, cancelled.diagnostic().code());
    }

    @Test
    void repeatedAnalysisIsDeterministicAndResultsAreImmutable() throws Exception {
        Stm32SignaturePack signaturePack = pack(signature("stm32f1.hal.HAL_Init.Os",
            "HAL_Init", PATTERN, allSpecifiedMask(PATTERN.length)));
        Stm32CtfEnrichmentContext context = context(List.of(
            new Stm32FunctionBytes(0x08000100L, PATTERN)));

        Stm32CtfEnrichmentReport first = ANALYZER.analyze(context, signaturePack,
            ParserLimits.defaults(), CancellationToken.none());
        assertEquals(first, ANALYZER.analyze(context, signaturePack,
            ParserLimits.defaults(), CancellationToken.none()));
        assertThrows(UnsupportedOperationException.class, () -> first.leads().clear());
        assertThrows(UnsupportedOperationException.class,
            () -> first.unsupportedCapabilities().clear());
        assertThrows(UnsupportedOperationException.class,
            () -> first.securityEvidence().pinnedWindowIds().clear());
        assertThrows(UnsupportedOperationException.class, () -> first.detectorsRun().clear());
    }

    private static Stm32CtfEnrichmentContext context(List<Stm32FunctionBytes> functions) {
        return new Stm32CtfEnrichmentContext(SELECTION,
            List.of(artifact(PART, "build-1", 0x08000000L)), functions,
            Optional.of("STM32F1"), Optional.of(COMPILER), Optional.of(OPTIMIZATION),
            Optional.empty());
    }

    private static Stm32CtfEnrichmentContext context(List<Stm32FunctionBytes> functions,
            String part) {
        return new Stm32CtfEnrichmentContext(SELECTION,
            List.of(artifact(part, "build-1", 0x08000000L)), functions,
            Optional.of("STM32F1"), Optional.of(COMPILER), Optional.of(OPTIMIZATION),
            Optional.empty());
    }

    private static Stm32FirmwareArtifact artifact(String part, String id, long base) {
        return new Stm32FirmwareArtifact(part, id, Stm32FirmwareRole.CANDIDATE,
            new Stm32VectorPlanner.ImageRange(base, 0x1000), "a".repeat(64),
            List.of(new Evidence(EvidenceKind.VERIFIED_CHECKSUM, "validated import",
                "Confirmed image extent and content digest")));
    }
}
