package io.github.rezabakhshi.embedra.targets.stm32.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.core.io.AddressRange;
import io.github.rezabakhshi.embedra.targets.stm32.catalog.Stm32CuratedPartIds;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.Test;

class Stm32VeneerPlannerTest {
    private static final Path ROOT = Path.of("catalogs/stm32/2026-09-29");

    private static final String HEADER_SHA256 =
        "c2ac14f09cc63e53d9eed5605038b7590d753f12fa3ace8d2ab209582d120f25";

    private static Stm32CuratedPartIds selection() throws Exception {
        return Stm32CuratedPartIds.load(ROOT.resolve("selection.json"),
            ParserLimits.defaults(), CancellationToken.none());
    }

    private static Stm32SecurityCatalog security() throws Exception {
        return Stm32SecurityCatalog.load(ROOT.resolve("security-domains.json"), selection(),
            ParserLimits.defaults(), CancellationToken.none());
    }

    private static Stm32SecurityHeaderSource header() {
        return new Stm32SecurityHeaderSource(
            "https://github.com/STMicroelectronics/cmsis-device-l5",
            "e237398c0cbae890f4659f74fe6b64cae339b6a0", "Include/stm32l552xx.h",
            HEADER_SHA256, "Apache-2.0");
    }

    private static Stm32SecurityRecord pinnedNsc(List<Stm32VeneerTransition> transitions) {
        Stm32SecurityWindow secure = new Stm32SecurityWindow("FLASH_S",
            Stm32SecurityWindow.Kind.FLASH, Stm32SecurityAttribute.SECURE,
            Stm32SecurityWindow.BoundaryKind.ALIAS_APERTURE, 0x0C000000L, 0x80000L, "FLASH",
            List.of("FLASH_SECURE_VIEW"), "FLASH_BASE_S", 1511, "(0x0C000000UL)",
            "Include/stm32l552xx.h",
            Stm32SecurityWindow.PartitionState.UNRESOLVED_CONFIGURATION_DEPENDENT);
        Stm32SecurityWindow nsc = new Stm32SecurityWindow("NSC_FLASH",
            Stm32SecurityWindow.Kind.FLASH, Stm32SecurityAttribute.NON_SECURE_CALLABLE,
            Stm32SecurityWindow.BoundaryKind.PARTITION, 0x0C040000L, 0x100L, "FLASH",
            List.of(), "FLASH_SECWM1R1", 7529, "FLASH_SECWM1R1_SECWM1_PEND",
            "Include/stm32l552xx.h",
            Stm32SecurityWindow.PartitionState.UNRESOLVED_CONFIGURATION_DEPENDENT);
        return new Stm32SecurityRecord("STM32L552ZET6Q",
            Stm32SecurityRecord.Status.ALIAS_VIEWS_PINNED, null, List.of(header()),
            List.of(secure, nsc), List.of(),
            new Stm32SecurityRecord.NscBoundary(Stm32SecurityRecord.EvidenceState.PINNED,
                "REVIEWED_NSC_BOUNDARY", List.of("FLASH_SECWM1R1_SECWM1_PEND")),
            new Stm32SecurityRecord.VeneerEvidence(Stm32SecurityRecord.EvidenceState.PINNED,
                "REVIEWED_NSC_BOUNDARY", null, transitions));
    }

    @Test
    void matchesOnlyWhenBoundaryTransitionAndEvidenceAgree() throws Exception {
        Stm32VeneerTransition transition = new Stm32VeneerTransition("veneer-1",
            new AddressRange("mcu", 0x0C040000L, 0x100L), "FLASH", "ev-1");
        Stm32SecurityRecord record = pinnedNsc(List.of(transition));
        Stm32VeneerPlanner.VeneerPlan plan = Stm32VeneerPlanner.plan(record,
            List.of(new Stm32VeneerPlanner.Candidate(0x0C040010L, "ev-1")),
            ParserLimits.defaults(), CancellationToken.none());
        assertEquals(Stm32VeneerPlanner.Status.MATCHED, plan.status());
        assertEquals(1, plan.matches().size());
        assertEquals("veneer-1", plan.matches().get(0).transitionId());
        assertEquals("FLASH", plan.matches().get(0).secureTargetRegionId());
        assertTrue(plan.rejections().isEmpty());
        assertEquals("PLANNED", plan.supportState());
    }

    @Test
    void wrongEvidenceAndUnreviewedAddressesAreRejected() throws Exception {
        Stm32VeneerTransition transition = new Stm32VeneerTransition("veneer-1",
            new AddressRange("mcu", 0x0C040000L, 0x100L), "FLASH", "ev-1");
        Stm32VeneerPlanner.VeneerPlan plan = Stm32VeneerPlanner.plan(
            pinnedNsc(List.of(transition)), List.of(
                new Stm32VeneerPlanner.Candidate(0x0C040010L, "other"),
                new Stm32VeneerPlanner.Candidate(0x0C090000L, "ev-1"),
                new Stm32VeneerPlanner.Candidate(0x0A000000L, "ev-1")),
            ParserLimits.defaults(), CancellationToken.none());
        assertEquals(Stm32VeneerPlanner.Status.NO_MATCH, plan.status());
        assertTrue(plan.matches().isEmpty());
        assertEquals(Stm32VeneerPlanner.Diagnostic.VENEER_EVIDENCE_MISMATCH,
            plan.rejections().get(0).diagnostic());
        assertEquals(Stm32VeneerPlanner.Diagnostic.VENEER_OUTSIDE_NSC,
            plan.rejections().get(1).diagnostic());
        assertEquals(Stm32VeneerPlanner.Diagnostic.VENEER_OUTSIDE_NSC,
            plan.rejections().get(2).diagnostic());
    }

    @Test
    void nscBoundaryWithoutATransitionStaysUnevidenced() throws Exception {
        Stm32VeneerPlanner.VeneerPlan plan = Stm32VeneerPlanner.plan(pinnedNsc(List.of()),
            List.of(new Stm32VeneerPlanner.Candidate(0x0C040010L, "ev-1")),
            ParserLimits.defaults(), CancellationToken.none());
        assertEquals(Stm32VeneerPlanner.Status.NO_MATCH, plan.status());
        assertEquals(Stm32VeneerPlanner.Diagnostic.VENEER_UNEVIDENCED,
            plan.rejections().get(0).diagnostic());
    }

    @Test
    void partWithoutPinnedNscRegionRejectsEverything() throws Exception {
        Stm32SecurityRecord l552 = security().requireRecord("STM32L552ZET6Q");
        Stm32VeneerPlanner.VeneerPlan plan = Stm32VeneerPlanner.plan(l552,
            List.of(new Stm32VeneerPlanner.Candidate(0x0C000010L, "ev-1")),
            ParserLimits.defaults(), CancellationToken.none());
        assertEquals(Stm32VeneerPlanner.Status.NO_MATCH, plan.status());
        assertEquals(Stm32VeneerPlanner.Diagnostic.NSC_REGION_NOT_PINNED,
            plan.rejections().get(0).diagnostic());
        assertFalse(l552.windows().isEmpty());
    }

    @Test
    void candidateLimitAndCancellationFailClosed() throws Exception {
        ParserLimits one = new ParserLimits(1024, 1024, 1024, 1, 4,
            Duration.ofSeconds(1));
        Stm32VeneerPlanner.VeneerPlan limited = Stm32VeneerPlanner.plan(
            pinnedNsc(List.of()), List.of(
                new Stm32VeneerPlanner.Candidate(0x0C040000L, "ev-1"),
                new Stm32VeneerPlanner.Candidate(0x0C040010L, "ev-1")),
            one, CancellationToken.none());
        assertEquals(Stm32VeneerPlanner.Status.LIMIT_EXCEEDED, limited.status());
        assertTrue(limited.matches().isEmpty());
        assertTrue(limited.rejections().isEmpty());
        assertThrows(DiagnosticException.class, () -> Stm32VeneerPlanner.plan(
            pinnedNsc(List.of()),
            List.of(new Stm32VeneerPlanner.Candidate(0x0C040000L, "ev-1")),
            ParserLimits.defaults(), () -> true));
    }
}
