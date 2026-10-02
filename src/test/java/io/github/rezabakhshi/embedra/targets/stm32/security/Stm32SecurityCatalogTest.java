package io.github.rezabakhshi.embedra.targets.stm32.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.targets.stm32.catalog.Stm32CuratedPartIds;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;

class Stm32SecurityCatalogTest {
    private static final Path ROOT = Path.of("catalogs/stm32/2026-09-29");

    private static final Path SELECTION = ROOT.resolve("selection.json");

    private static final Path SECURITY = ROOT.resolve("security-domains.json");

    private static Stm32CuratedPartIds selection() throws Exception {
        return Stm32CuratedPartIds.load(SELECTION, ParserLimits.defaults(),
            CancellationToken.none());
    }

    private static Stm32SecurityCatalog catalog() throws Exception {
        return Stm32SecurityCatalog.load(SECURITY, selection(), ParserLimits.defaults(),
            CancellationToken.none());
    }

    private static byte[] replaceFirst(byte[] input, String target, String replacement) {
        String text = new String(input, StandardCharsets.UTF_8);
        int index = text.indexOf(target);
        assertTrue(index >= 0, "missing pattern: " + target);
        return text.replaceFirst(java.util.regex.Pattern.quote(target),
            java.util.regex.Matcher.quoteReplacement(replacement))
            .getBytes(StandardCharsets.UTF_8);
    }

    private static IOException parseFailure(byte[] input) throws Exception {
        ParserLimits limits = ParserLimits.defaults();
        CancellationToken token = CancellationToken.none();
        return assertThrows(IOException.class, () -> Stm32SecurityCatalog.parse(input,
            sha256(input), selection(), limits, token));
    }

    private static String sha256(byte[] input) throws Exception {
        return HexFormat.of().formatHex(
            MessageDigest.getInstance("SHA-256").digest(input));
    }

    @Test
    void loadsDigestPinnedSnapshotWithExplicitAvailability() throws Exception {
        Stm32SecurityCatalog catalog = catalog();
        assertEquals(53, catalog.size());
        assertEquals(19, catalog.aliasViewParts());
        assertEquals(34, catalog.unavailableParts());
        assertEquals(19, catalog.records().stream()
            .filter(Stm32SecurityRecord::pinned).count());
        Stm32SecurityRecord h503 = catalog.requireRecord("STM32H503RBT6");
        assertFalse(h503.pinned());
        assertEquals("NON_SECURE_SUFFIXED_ALIASES_ONLY", h503.reason());
        assertTrue(h503.windows().isEmpty());
    }

    @Test
    void resolvesOnlyExactPartRecordsNeverFamilyOrWildcard() throws Exception {
        Stm32SecurityCatalog catalog = catalog();
        Stm32SecurityRecord l552 = catalog.requireRecord("STM32L552ZET6Q");
        assertTrue(l552.pinned());
        assertThrows(IllegalArgumentException.class,
            () -> catalog.requireRecord("STM32L552ZET6"));
        assertThrows(IllegalArgumentException.class,
            () -> catalog.requireRecord("STM32L5"));
    }

    @Test
    void pinnedRecordCarriesEvidencedAliasAperturesAndSecureFault() throws Exception {
        Stm32SecurityRecord l552 = catalog().requireRecord("STM32L552ZET6Q");
        assertEquals(3, l552.windows().size());
        Stm32SecurityWindow flash = l552.windows().stream()
            .filter(window -> window.id().equals("FLASH_S"))
            .findFirst()
            .orElseThrow();
        assertEquals(Stm32SecurityAttribute.SECURE, flash.attribute());
        assertEquals(Stm32SecurityWindow.BoundaryKind.ALIAS_APERTURE, flash.boundaryKind());
        assertEquals(0x0C000000L, flash.start());
        assertEquals(0x80000L, flash.size());
        assertEquals("FLASH", flash.pairedRegionId());
        assertTrue(flash.pairedAliasIds().contains("FLASH_SECURE_VIEW"));
        assertEquals("FLASH_BASE_S", flash.baseSymbol());
        assertEquals(1, l552.sourceHeaders().size());
        assertEquals("c2ac14f09cc63e53d9eed5605038b7590d753f12fa3ace8d2ab209582d120f25",
            l552.sourceHeaders().get(0).sha256());
        assertEquals(Stm32SecurityRecord.EvidenceState.UNAVAILABLE,
            l552.nonSecureCallable().status());
        assertEquals("NSC_REGION_CONFIGURATION_DEPENDENT", l552.nonSecureCallable().reason());
        assertFalse(l552.nonSecureCallable().configurationEvidence().isEmpty());
        assertEquals("SecureFault_IRQn",
            l552.veneerEvidence().secureFaultException().name());
        assertEquals(-9, l552.veneerEvidence().secureFaultException().number());
    }

    @Test
    void tamperedDigestIsRejected() throws Exception {
        byte[] bytes = Files.readAllBytes(SECURITY);
        byte[] modified = bytes.clone();
        for (int index = 0; index < modified.length; index++) {
            if (modified[index] == 'S') {
                modified[index] = 'T';
                break;
            }
        }
        Path tampered = Files.createTempFile("security-domains", ".json");
        try {
            Files.write(tampered, modified);
            Stm32CuratedPartIds selection = selection();
            assertThrows(IOException.class, () -> Stm32SecurityCatalog.load(tampered,
                selection, ParserLimits.defaults(), CancellationToken.none()));
        }
        finally {
            Files.deleteIfExists(tampered);
        }
    }

    @Test
    void unknownAttributeFailsClosed() throws Exception {
        byte[] modified = replaceFirst(Files.readAllBytes(SECURITY), "\"attribute\":\"SECURE\"",
            "\"attribute\":\"SECUREISH\"");
        assertTrue(parseFailure(modified).getMessage()
            .contains("Unknown security window value"));
    }

    @Test
    void outOfRangeWindowFailsClosed() throws Exception {
        byte[] modified = replaceFirst(Files.readAllBytes(SECURITY), "\"start\":201326592",
            "\"start\":4294967296");
        assertTrue(parseFailure(modified).getMessage().contains("invalid"));
    }

    @Test
    void duplicateWindowIdFailsClosed() throws Exception {
        byte[] modified = replaceFirst(Files.readAllBytes(SECURITY), "\"id\":\"FLASH_S\"",
            "\"id\":\"SRAM1_S\"");
        assertTrue(parseFailure(modified).getMessage().contains("invalid"));
    }

    @Test
    void missingWindowFieldFailsClosed() throws Exception {
        byte[] modified = replaceFirst(Files.readAllBytes(SECURITY), "\"kind\":\"FLASH\",",
            "");
        assertTrue(parseFailure(modified).getMessage().contains("schema"));
    }

    @Test
    void nonCuratedAndDuplicatePartsFailClosed() throws Exception {
        byte[] unknown = replaceFirst(Files.readAllBytes(SECURITY),
            "\"exactPart\":\"STM32L552ZET6Q\"", "\"exactPart\":\"STM32L599ZET6Q\"");
        assertTrue(parseFailure(unknown).getMessage().contains("curated"));
        byte[] duplicate = replaceFirst(Files.readAllBytes(SECURITY),
            "\"exactPart\":\"STM32L552ZET6Q\"", "\"exactPart\":\"STM32L562QEI6Q\"");
        assertTrue(parseFailure(duplicate).getMessage().contains("Duplicate"));
    }

    @Test
    void wrongPinnedRootDigestFailsClosed() throws Exception {
        byte[] modified = replaceFirst(Files.readAllBytes(SECURITY),
            Stm32MemoryPlannerDigests.MEMORY_PLANS_SHA256, "0".repeat(64));
        assertTrue(parseFailure(modified).getMessage().contains("pins"));
    }

    @Test
    void truncatedAndOversizedInputsFailClosed() throws Exception {
        byte[] bytes = Files.readAllBytes(SECURITY);
        byte[] truncated = java.util.Arrays.copyOf(bytes, bytes.length / 2);
        assertThrows(io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException.class,
            () -> Stm32SecurityCatalog.parse(truncated, sha256(truncated), selection(),
                ParserLimits.defaults(), CancellationToken.none()));
        ParserLimits tiny = new ParserLimits(1024, 1024, 1024, 10, 4,
            Duration.ofSeconds(1));
        assertThrows(IOException.class, () -> Stm32SecurityCatalog.parse(bytes,
            Stm32SecurityCatalog.SHA256, selection(), tiny, CancellationToken.none()));
    }

    /** Local constant holder; the planner's pin is the reviewed memory-plan digest. */
    private static final class Stm32MemoryPlannerDigests {
        private static final String MEMORY_PLANS_SHA256 =
            "00def2817ba0660644a4bc6cea3ffb756e11aff4d7236a466f82de838c280c66";
    }
}
