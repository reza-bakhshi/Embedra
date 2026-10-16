package io.github.rezabakhshi.embedra.analyzers.stm8;

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

class Stm8SignatureMatcherTest {

    private static final Stm8SignaturePack BUILTIN_PACK = Stm8SignaturePack.builtin();

    @Test
    void matchesSplRoutinesUnderSdccEvidence() throws Exception {
        // SDCC GPIO_Init pattern from pack
        byte[] gpioInitPattern = new byte[] {
            (byte) 0x89, (byte) 0x88, 0x7B, 0x03, (byte) 0xA1, 0x00, 0x27, 0x05,
            0x6B, 0x00, (byte) 0x81, (byte) 0x84, (byte) 0x85, (byte) 0x81, (byte) 0x9D, (byte) 0x81
        };

        // CLK_DeInit pattern from pack
        byte[] clkDeInitPattern = new byte[] {
            0x35, 0x01, 0x50, (byte) 0xC0, 0x35, 0x00, 0x50, (byte) 0xC1,
            0x35, (byte) 0xE1, 0x50, (byte) 0xC4, 0x35, 0x00, 0x50, (byte) 0xC5,
            (byte) 0x81, (byte) 0x9D
        };

        Stm8SignatureContext context = new Stm8SignatureContext(
                "STM8S003F3P6",
                "STM8S",
                Optional.of("SDCC"),
                Optional.of("-Os"),
                List.of(
                        new Stm8FunctionBytes(0x008100L, gpioInitPattern),
                        new Stm8FunctionBytes(0x008200L, clkDeInitPattern)
                ));

        Stm8SignatureMatchReport report = Stm8SignatureMatcher.match(
                context, BUILTIN_PACK, ParserLimits.defaults(), CancellationToken.none());

        assertEquals(2, report.matches().size());
        assertEquals(2, report.functionsScanned());
        assertEquals("GPIO_Init", report.matches().get(0).functionName());
        assertEquals(0x008100L, report.matches().get(0).address());
        assertEquals(Confidence.VERIFIED, report.matches().get(0).confidence());
        assertEquals(EvidenceKind.EXACT_SIGNATURE_MATCH, report.matches().get(0).evidence().get(0).kind());

        assertEquals("CLK_DeInit", report.matches().get(1).functionName());
        assertEquals(0x008200L, report.matches().get(1).address());
        assertTrue(report.nonMatches().isEmpty());
    }

    @Test
    void matchesSdccCompilerRuntimeHelpers() throws Exception {
        byte[] divsintPattern = new byte[] {
            (byte) 0x89, 0x7B, 0x03, 0x26, 0x06, 0x7B, 0x04, 0x27, 0x0A,
            0x62, (byte) 0x85, (byte) 0x81, (byte) 0x85, (byte) 0x81, (byte) 0x80, (byte) 0x81
        };

        byte[] mullongPattern = new byte[] {
            (byte) 0x89, (byte) 0x90, (byte) 0x89, 0x7B, 0x07, 0x42,
            (byte) 0x90, 0x1F, 0x01, (byte) 0x90, (byte) 0x85, (byte) 0x85,
            (byte) 0x81, (byte) 0x9D, (byte) 0x81, (byte) 0x81
        };

        byte[] mulintPattern = new byte[] {
            (byte) 0x88, (byte) 0x90, (byte) 0xAE, 0x00, 0x00, 0x7B, 0x04,
            0x42, (byte) 0x84, (byte) 0x81, (byte) 0x9D, (byte) 0x9D,
            (byte) 0x81, (byte) 0x81, (byte) 0x9D, (byte) 0x81
        };

        Stm8SignatureContext context = new Stm8SignatureContext(
                "STM8S103F3P6",
                "STM8S",
                Optional.of("SDCC"),
                Optional.of("-Os"),
                List.of(
                        new Stm8FunctionBytes(0x008300L, divsintPattern),
                        new Stm8FunctionBytes(0x008340L, mullongPattern),
                        new Stm8FunctionBytes(0x008380L, mulintPattern)
                ));

        Stm8SignatureMatchReport report = Stm8SignatureMatcher.match(
                context, BUILTIN_PACK, ParserLimits.defaults(), CancellationToken.none());

        assertEquals(3, report.matches().size());
        assertEquals("__divsint", report.matches().get(0).functionName());
        assertEquals("__mullong", report.matches().get(1).functionName());
        assertEquals("__mulint", report.matches().get(2).functionName());
    }

    @Test
    void matchesCosmicCompilerRuntimeHelpers() throws Exception {
        byte[] switchPattern = new byte[] {
            0x7B, 0x03, (byte) 0xD1, 0x00, 0x00, 0x27, 0x05, 0x5C,
            0x20, (byte) 0xF7, (byte) 0x81, (byte) 0x9D, (byte) 0x81, (byte) 0x9D, (byte) 0x81, (byte) 0x81
        };

        byte[] idivPattern = new byte[] {
            (byte) 0x89, (byte) 0x90, (byte) 0x89, 0x7B, 0x03, 0x62,
            (byte) 0x90, (byte) 0x85, (byte) 0x85, (byte) 0x81, (byte) 0x9D,
            (byte) 0x81, (byte) 0x9D, (byte) 0x81, (byte) 0x81, (byte) 0x81
        };

        Stm8SignatureContext context = new Stm8SignatureContext(
                "STM8L151C8T6",
                "STM8L",
                Optional.of("COSMIC"),
                Optional.of("-Os"),
                List.of(
                        new Stm8FunctionBytes(0x008400L, switchPattern),
                        new Stm8FunctionBytes(0x008440L, idivPattern)
                ));

        Stm8SignatureMatchReport report = Stm8SignatureMatcher.match(
                context, BUILTIN_PACK, ParserLimits.defaults(), CancellationToken.none());

        assertEquals(2, report.matches().size());
        assertEquals("_switch", report.matches().get(0).functionName());
        assertEquals("_i_div", report.matches().get(1).functionName());
    }

    @Test
    void missingEvidenceRejectsGuessedMatchesPerStm8009() throws Exception {
        byte[] dummy = new byte[] {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte) 0x88};
        Stm8FunctionBytes func = new Stm8FunctionBytes(0x008080L, dummy);

        // Missing compiler
        Stm8SignatureContext noCompiler = new Stm8SignatureContext(
                "STM8S003F3P6", "STM8S", Optional.empty(), Optional.of("-Os"), List.of(func));
        Stm8SignatureMatchReport report1 = Stm8SignatureMatcher.match(
                noCompiler, BUILTIN_PACK, ParserLimits.defaults(), CancellationToken.none());

        assertTrue(report1.matches().isEmpty());
        assertEquals(1, report1.nonMatches().size());
        assertEquals(Stm8SignatureNonMatch.Kind.EVIDENCE_MISSING, report1.nonMatches().get(0).kind());

        // Unavailable index
        Stm8SignatureContext unknownCompiler = new Stm8SignatureContext(
                "STM8S003F3P6", "STM8S", Optional.of("UNKNOWN_COMPILER"), Optional.of("-Os"), List.of(func));
        Stm8SignatureMatchReport report2 = Stm8SignatureMatcher.match(
                unknownCompiler, BUILTIN_PACK, ParserLimits.defaults(), CancellationToken.none());

        assertTrue(report2.matches().isEmpty());
        assertEquals(Stm8SignatureNonMatch.Kind.INDEX_UNAVAILABLE, report2.nonMatches().get(0).kind());
    }

    @Test
    void respectsCancellationAndParserLimits() {
        byte[] dummy = new byte[] {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte) 0x88};
        Stm8SignatureContext context = new Stm8SignatureContext(
                "STM8S003F3P6", "STM8S", Optional.of("SDCC"), Optional.of("-Os"),
                List.of(new Stm8FunctionBytes(0x008080L, dummy)));

        // Cancellation
        CancellationToken cancelled = () -> true;
        assertThrows(DiagnosticException.class, () ->
                Stm8SignatureMatcher.match(context, BUILTIN_PACK, ParserLimits.defaults(), cancelled));

        // Limit exceeded
        ParserLimits tightLimits = new ParserLimits(
                1_000_000, 1_000_000, 1_000_000, 2, 10, java.time.Duration.ofSeconds(1));
        assertThrows(DiagnosticException.class, () ->
                Stm8SignatureMatcher.match(context, BUILTIN_PACK, tightLimits, CancellationToken.none()));
    }
}
