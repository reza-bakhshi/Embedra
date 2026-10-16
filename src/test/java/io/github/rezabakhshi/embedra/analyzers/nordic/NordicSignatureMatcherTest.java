package io.github.rezabakhshi.embedra.analyzers.nordic;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.core.model.Confidence;
import io.github.rezabakhshi.embedra.core.model.EvidenceKind;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class NordicSignatureMatcherTest {

    private static final NordicSignaturePack BUILTIN_PACK = NordicSignaturePack.builtin();

    @Test
    void matchesBleRoutinesUnderNrf52Evidence() throws Exception {
        byte[] bleAdvStart = new byte[] {
            0x10, (byte) 0xB5, 0x73, (byte) 0xDF, 0x10, (byte) 0xBD, 0x00, (byte) 0xBF
        };
        byte[] bleGattsAdd = new byte[] {
            0x30, (byte) 0xB5, (byte) 0xA8, (byte) 0xDF, 0x30, (byte) 0xBD, 0x00, (byte) 0xBF
        };

        NordicSignatureContext context = new NordicSignatureContext(
                "nRF52840-QIAA",
                "nRF52",
                Optional.of("ANY"),
                Optional.empty(),
                List.of(
                        new NordicFunctionBytes(0x00026100L, bleAdvStart),
                        new NordicFunctionBytes(0x00026200L, bleGattsAdd)
                ));

        NordicSignatureMatchReport report = NordicSignatureMatcher.match(
                context, BUILTIN_PACK, ParserLimits.defaults(), CancellationToken.none());

        assertEquals(2, report.matches().size());
        assertEquals(2, report.functionsScanned());
        assertEquals("sd_ble_gap_adv_start", report.matches().get(0).functionName());
        assertEquals(0x00026100L, report.matches().get(0).address());
        assertEquals(Confidence.VERIFIED, report.matches().get(0).confidence());
        assertEquals(EvidenceKind.EXACT_SIGNATURE_MATCH, report.matches().get(0).evidence().get(0).kind());

        assertEquals("sd_ble_gatts_service_add", report.matches().get(1).functionName());
        assertEquals(0x00026200L, report.matches().get(1).address());
        assertTrue(report.nonMatches().isEmpty());
    }

    @Test
    void matchesNcsZephyrRoutinesUnderNrf53Evidence() throws Exception {
        byte[] btEnable = new byte[] {
            0x30, (byte) 0xB5, 0x04, 0x46, 0x12, 0x34, 0x56, 0x78, 0x30, (byte) 0xBD
        };
        byte[] zCstart = new byte[] {
            0x10, (byte) 0xB5, 0x01, 0x48, 0x10, (byte) 0xBD, 0x00, (byte) 0xBF, 0x00, 0x00, 0x00, 0x20
        };

        NordicSignatureContext context = new NordicSignatureContext(
                "nRF5340-QKAA",
                "nRF53",
                Optional.of("ANY"),
                Optional.empty(),
                List.of(
                        new NordicFunctionBytes(0x00010000L, btEnable),
                        new NordicFunctionBytes(0x00010100L, zCstart)
                ));

        NordicSignatureMatchReport report = NordicSignatureMatcher.match(
                context, BUILTIN_PACK, ParserLimits.defaults(), CancellationToken.none());

        assertEquals(2, report.matches().size());
        assertEquals("bt_enable", report.matches().get(0).functionName());
        assertEquals(Confidence.DERIVED, report.matches().get(0).confidence()); // Masked BL call
        assertEquals("z_cstart", report.matches().get(1).functionName());
    }

    @Test
    void reportsIndexUnavailableWhenSeriesUnsupported() throws Exception {
        NordicSignaturePack singleSeriesPack = new NordicSignaturePack(
                "custom-pack", "1.0", List.of("nRF51"),
                List.of(new NordicLibrarySignature(
                        "custom.sig", "LIB", "SUB", "fn", "nRF51", "ANY", "-O2",
                        "f.c", "2a9754f9a56291a89c323f4625b525d8c3681432f418d184715f8d9b626488a0",
                        new byte[8], new byte[] {(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
                                (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF})));

        NordicSignatureContext context = new NordicSignatureContext(
                "nRF9160-SICA",
                "nRF91",
                Optional.of("ANY"),
                Optional.empty(),
                List.of(new NordicFunctionBytes(0x00010000L, new byte[16])));

        NordicSignatureMatchReport report = NordicSignatureMatcher.match(
                context, singleSeriesPack, ParserLimits.defaults(), CancellationToken.none());

        assertTrue(report.matches().isEmpty());
        assertEquals(1, report.nonMatches().size());
        assertEquals(NordicSignatureNonMatch.Kind.INDEX_UNAVAILABLE, report.nonMatches().get(0).kind());
    }

    @Test
    void rejectsExcessiveFunctionCountUnderParserLimits() {
        ParserLimits limits = new ParserLimits(
                1_000_000, 1_000_000, 1_000_000, 10, 10, java.time.Duration.ofSeconds(5));

        List<NordicFunctionBytes> funcs = new ArrayList<>();
        for (int i = 0; i < 20; i++) {
            funcs.add(new NordicFunctionBytes(0x1000L + (i * 16), new byte[16]));
        }

        NordicSignatureContext context = new NordicSignatureContext(
                "nRF52840-QIAA", "nRF52", Optional.empty(), Optional.empty(), funcs);

        DiagnosticException ex = assertThrows(DiagnosticException.class, () ->
                NordicSignatureMatcher.match(context, BUILTIN_PACK, limits, CancellationToken.none()));
        assertEquals(DiagnosticCode.LIMIT_EXCEEDED, ex.diagnostic().code());
    }

    @Test
    void respectsCooperativeCancellation() {
        CancellationToken cancelled = () -> true;
        NordicSignatureContext context = new NordicSignatureContext(
                "nRF52840-QIAA", "nRF52", Optional.empty(), Optional.empty(),
                List.of(new NordicFunctionBytes(0x1000L, new byte[16])));

        assertThrows(Exception.class, () ->
                NordicSignatureMatcher.match(context, BUILTIN_PACK, ParserLimits.defaults(), cancelled));
    }
}
