package io.github.rezabakhshi.embedra.analyzers.atmel;

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

class AtmelSignatureMatcherTest {

    private static final AtmelSignaturePack BUILTIN_PACK = AtmelSignaturePack.builtin();

    @Test
    void matchesAvrRoutinesUnderAtmegaEvidence() throws Exception {
        byte[] avrInit = new byte[] {
            (byte) 0x78, (byte) 0x94, (byte) 0x84, (byte) 0xE0, (byte) 0x80, (byte) 0x93, (byte) 0x6E, (byte) 0x00
        };
        byte[] avrPinMode = new byte[] {
            (byte) 0x08, (byte) 0x95, (byte) 0x88, (byte) 0x23, (byte) 0x99, (byte) 0x27, (byte) 0x80, (byte) 0x91
        };
        byte[] avrMalloc = new byte[] {
            (byte) 0xCF, (byte) 0x93, (byte) 0xDF, (byte) 0x93, (byte) 0x00, (byte) 0xD0, (byte) 0xCD, (byte) 0xB7
        };

        AtmelSignatureContext context = new AtmelSignatureContext(
                "ATmega328P",
                "ATmega",
                "AVR8",
                Optional.of("ANY"),
                Optional.empty(),
                List.of(
                        new AtmelFunctionBytes(0x00000100L, avrInit),
                        new AtmelFunctionBytes(0x00000200L, avrPinMode),
                        new AtmelFunctionBytes(0x00000300L, avrMalloc)
                ));

        AtmelSignatureMatchReport report = AtmelSignatureMatcher.match(
                context, BUILTIN_PACK, ParserLimits.defaults(), CancellationToken.none());

        assertEquals(3, report.matches().size());
        assertEquals(3, report.functionsScanned());

        assertEquals("init", report.matches().get(0).functionName());
        assertEquals(0x00000100L, report.matches().get(0).address());
        assertEquals(Confidence.VERIFIED, report.matches().get(0).confidence());
        assertEquals(EvidenceKind.EXACT_SIGNATURE_MATCH, report.matches().get(0).evidence().get(0).kind());

        assertEquals("pinMode", report.matches().get(1).functionName());
        assertEquals(0x00000200L, report.matches().get(1).address());

        assertEquals("malloc", report.matches().get(2).functionName());
        assertEquals(0x00000300L, report.matches().get(2).address());
        assertTrue(report.nonMatches().isEmpty());
    }

    @Test
    void matchesSamRoutinesUnderSamdEvidence() throws Exception {
        byte[] samSystemInit = new byte[] {
            (byte) 0x80, (byte) 0xB5, (byte) 0x82, (byte) 0xB0, (byte) 0x12, (byte) 0x34, (byte) 0x56, (byte) 0x78
        };
        byte[] samDelayMs = new byte[] {
            (byte) 0x10, (byte) 0xB5, (byte) 0x4F, (byte) 0xF4, (byte) 0x7A, (byte) 0x71, (byte) 0x01, (byte) 0xFB
        };
        byte[] samTaskCreate = new byte[] {
            (byte) 0x2D, (byte) 0xE9, (byte) 0xF0, (byte) 0x41, (byte) 0x85, (byte) 0xB0, (byte) 0x00, (byte) 0x20
        };

        AtmelSignatureContext context = new AtmelSignatureContext(
                "SAMD21G18A",
                "SAMD",
                "ARM_THUMB",
                Optional.of("ANY"),
                Optional.empty(),
                List.of(
                        new AtmelFunctionBytes(0x00001000L, samSystemInit),
                        new AtmelFunctionBytes(0x00001100L, samDelayMs),
                        new AtmelFunctionBytes(0x00001200L, samTaskCreate)
                ));

        AtmelSignatureMatchReport report = AtmelSignatureMatcher.match(
                context, BUILTIN_PACK, ParserLimits.defaults(), CancellationToken.none());

        assertEquals(3, report.matches().size());
        assertEquals("system_init", report.matches().get(0).functionName());
        assertEquals(Confidence.DERIVED, report.matches().get(0).confidence()); // Masked call
        assertEquals("delay_ms", report.matches().get(1).functionName());
        assertEquals("xTaskCreate", report.matches().get(2).functionName());
    }

    @Test
    void reportsIndexUnavailableWhenSeriesUnsupported() throws Exception {
        AtmelSignaturePack singleSeriesPack = new AtmelSignaturePack(
                "custom-pack", "1.0", List.of("ATmega"),
                List.of(new AtmelLibrarySignature(
                        "custom.sig", "LIB", "SUB", "fn", "AVR8", "ATmega", "ANY", "-O2",
                        "f.c", "2a9754f9a56291a89c323f4625b525d8c3681432f418d184715f8d9b626488a0",
                        new byte[8], new byte[] {(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
                                (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF})));

        AtmelSignatureContext context = new AtmelSignatureContext(
                "SAML11E16A",
                "SAML",
                "ARM_THUMB",
                Optional.of("ANY"),
                Optional.empty(),
                List.of(new AtmelFunctionBytes(0x00001000L, new byte[16])));

        AtmelSignatureMatchReport report = AtmelSignatureMatcher.match(
                context, singleSeriesPack, ParserLimits.defaults(), CancellationToken.none());

        assertTrue(report.matches().isEmpty());
        assertEquals(1, report.nonMatches().size());
        assertEquals(AtmelSignatureNonMatch.Kind.INDEX_UNAVAILABLE, report.nonMatches().get(0).kind());
    }

    @Test
    void enforcesLimitsAndCancellation() {
        CancellationToken cancelled = () -> true;
        AtmelSignatureContext context = new AtmelSignatureContext(
                "ATmega328P", "ATmega", "AVR8", Optional.empty(), Optional.empty(), List.of());

        assertThrows(DiagnosticException.class, () ->
                AtmelSignatureMatcher.match(context, BUILTIN_PACK, ParserLimits.defaults(), cancelled));

        List<AtmelFunctionBytes> tooMany = new ArrayList<>();
        for (int i = 0; i < 20; i++) {
            tooMany.add(new AtmelFunctionBytes(i * 16, new byte[8]));
        }
        AtmelSignatureContext overflowContext = new AtmelSignatureContext(
                "ATmega328P", "ATmega", "AVR8", Optional.empty(), Optional.empty(), tooMany);

        ParserLimits tightLimits = new ParserLimits(
                1_000_000, 1_000_000, 1_000_000, 5, 10, java.time.Duration.ofSeconds(5));
        DiagnosticException de = assertThrows(DiagnosticException.class, () ->
                AtmelSignatureMatcher.match(overflowContext, BUILTIN_PACK, tightLimits, CancellationToken.none()));
        assertEquals(DiagnosticCode.LIMIT_EXCEEDED, de.diagnostic().code());
    }
}
