package io.github.rezabakhshi.embedra.analyzers.stm32;

import static io.github.rezabakhshi.embedra.analyzers.stm32.Stm32SignatureTestSupport.context;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.core.model.Confidence;
import io.github.rezabakhshi.embedra.core.model.EvidenceKind;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class Stm32SignatureMatcherTest {
    private static final byte[] PATTERN =
        {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte) 0x88};

    @Test
    void matchesIndexedSignatureWithExactConfidence() throws Exception {
        Stm32LibrarySignature signature = Stm32SignatureTestSupport.signature(
            "stm32f1.hal.HAL_Init.Os", "HAL_Init", PATTERN,
            Stm32SignatureTestSupport.allSpecifiedMask(PATTERN.length));
        Stm32SignatureContext context = context(Optional.of(Stm32SignatureTestSupport.COMPILER),
            Optional.of("-Os"), "STM32F1", new Stm32FunctionBytes(0x8000100L, PATTERN));
        Stm32SignatureMatchReport report = match(context,
            Stm32SignatureTestSupport.pack(signature));
        assertEquals(1, report.matches().size());
        assertEquals(1, report.functionsScanned());
        assertEquals(1, report.signaturesIndexed());
        assertEquals(Confidence.VERIFIED, report.matches().get(0).confidence());
        assertEquals(EvidenceKind.EXACT_SIGNATURE_MATCH,
            report.matches().get(0).evidence().get(0).kind());
        assertTrue(report.nonMatches().isEmpty());
    }

    @Test
    void maskedSignatureUsesDerivedConfidence() throws Exception {
        byte[] mask = Stm32SignatureTestSupport.allSpecifiedMask(PATTERN.length);
        mask[3] = 0;
        Stm32LibrarySignature signature = Stm32SignatureTestSupport.signature(
            "stm32f1.hal.HAL_Init.Os", "HAL_Init", PATTERN, mask);
        Stm32SignatureContext context = context(Optional.of(Stm32SignatureTestSupport.COMPILER),
            Optional.of("-Os"), "STM32F1",
            new Stm32FunctionBytes(0x8000100L,
                new byte[] {0x11, 0x22, 0x33, (byte) 0xAA, 0x55, 0x66, 0x77, (byte) 0x88}));
        Stm32SignatureMatchReport report = match(context,
            Stm32SignatureTestSupport.pack(signature));
        assertEquals(Confidence.DERIVED, report.matches().get(0).confidence());
        assertEquals(EvidenceKind.DERIVED_RULE,
            report.matches().get(0).evidence().get(0).kind());
    }

    @Test
    void missingEvidenceAppliesNothing() throws Exception {
        Stm32LibrarySignature signature = Stm32SignatureTestSupport.signature(
            "stm32f1.hal.HAL_Init.Os", "HAL_Init", PATTERN,
            Stm32SignatureTestSupport.allSpecifiedMask(PATTERN.length));
        Stm32FunctionBytes function = new Stm32FunctionBytes(0x8000100L, PATTERN);

        Stm32SignatureMatchReport noCompiler = match(
            context(Optional.empty(), Optional.of("-Os"), "STM32F1", function),
            Stm32SignatureTestSupport.pack(signature));
        assertTrue(noCompiler.matches().isEmpty());
        assertEquals(0, noCompiler.functionsScanned());
        assertEquals(Stm32SignatureNonMatch.Kind.EVIDENCE_MISSING,
            noCompiler.nonMatches().get(0).kind());

        Stm32SignatureMatchReport blankFamily = match(
            context(Optional.of(Stm32SignatureTestSupport.COMPILER), Optional.of("-Os"), "", function),
            Stm32SignatureTestSupport.pack(signature));
        assertEquals(Stm32SignatureNonMatch.Kind.EVIDENCE_MISSING,
            blankFamily.nonMatches().get(0).kind());
    }

    @Test
    void unavailableIndexDoesNotGuess() throws Exception {
        Stm32LibrarySignature signature = new Stm32LibrarySignature(
            "stm32f1.hal.HAL_Init.O2", "stm32f1xx-hal", "stm32f1xx-hal", "HAL_Init",
            "STM32F1", Stm32SignatureTestSupport.COMPILER, "-O2",
            "Drivers/STM32F1xx_HAL_Driver/Src/stm32f1xx_hal.c",
            Stm32SignatureTestSupport.SOURCE_SHA, PATTERN,
            Stm32SignatureTestSupport.allSpecifiedMask(PATTERN.length));
        Stm32SignatureContext context = context(Optional.of(Stm32SignatureTestSupport.COMPILER),
            Optional.of("-Os"), "STM32F1", new Stm32FunctionBytes(0x8000100L, PATTERN));
        Stm32SignatureMatchReport report = match(context,
            Stm32SignatureTestSupport.pack(signature));
        assertEquals(Stm32SignatureNonMatch.Kind.INDEX_UNAVAILABLE,
            report.nonMatches().get(0).kind());
        assertEquals(0, report.functionsScanned());
    }

    @Test
    void unmatchedFunctionIsExplicitNonMatch() throws Exception {
        Stm32LibrarySignature signature = Stm32SignatureTestSupport.signature(
            "stm32f1.hal.HAL_Init.Os", "HAL_Init", PATTERN,
            Stm32SignatureTestSupport.allSpecifiedMask(PATTERN.length));
        Stm32SignatureContext context = context(Optional.of(Stm32SignatureTestSupport.COMPILER),
            Optional.of("-Os"), "STM32F1", new Stm32FunctionBytes(0x8000200L, new byte[8]));
        Stm32SignatureMatchReport report = match(context,
            Stm32SignatureTestSupport.pack(signature));
        assertTrue(report.matches().isEmpty());
        assertEquals(Stm32SignatureNonMatch.Kind.NO_MATCH,
            report.nonMatches().get(0).kind());
    }

    @Test
    void unmatchedDetailsAreBounded() throws Exception {
        Stm32LibrarySignature signature = Stm32SignatureTestSupport.signature(
            "stm32f1.hal.HAL_Init.Os", "HAL_Init", PATTERN,
            Stm32SignatureTestSupport.allSpecifiedMask(PATTERN.length));
        List<Stm32FunctionBytes> functions = new ArrayList<>();
        for (int index = 0; index < 500; index++) {
            functions.add(new Stm32FunctionBytes(0x8000000L + index, new byte[8]));
        }
        Stm32SignatureContext context = new Stm32SignatureContext("STM32F103C8T6",
            "STM32F1", Optional.of(Stm32SignatureTestSupport.COMPILER), Optional.of("-Os"),
            functions);
        Stm32SignatureMatchReport report = match(context,
            Stm32SignatureTestSupport.pack(signature));
        assertEquals(500, report.functionsScanned());
        assertEquals(129, report.nonMatches().size());
    }

    @Test
    void rejectsOversizedInputAndCancellation() throws Exception {
        Stm32LibrarySignature signature = Stm32SignatureTestSupport.signature(
            "stm32f1.hal.HAL_Init.Os", "HAL_Init", PATTERN,
            Stm32SignatureTestSupport.allSpecifiedMask(PATTERN.length));
        Stm32SignaturePack pack = Stm32SignatureTestSupport.pack(signature);
        Stm32SignatureContext context = context(Optional.of(Stm32SignatureTestSupport.COMPILER),
            Optional.of("-Os"), "STM32F1", new Stm32FunctionBytes(0x8000100L, PATTERN));
        ParserLimits tinyObjects = new ParserLimits(1024, 1024, 1024, 1, 32,
            Duration.ofSeconds(30));
        DiagnosticException limited = assertThrows(DiagnosticException.class,
            () -> Stm32SignatureMatcher.match(context, pack, tinyObjects, CancellationToken.none()));
        assertEquals(DiagnosticCode.LIMIT_EXCEEDED, limited.diagnostic().code());
        ParserLimits tinyBytes = new ParserLimits(4, 1024, 1024, 100, 32,
            Duration.ofSeconds(30));
        assertThrows(DiagnosticException.class,
            () -> Stm32SignatureMatcher.match(context, pack, tinyBytes, CancellationToken.none()));

        DiagnosticException cancelled = assertThrows(DiagnosticException.class,
            () -> Stm32SignatureMatcher.match(context, pack, ParserLimits.defaults(),
                () -> true));
        assertEquals(DiagnosticCode.CANCELLED, cancelled.diagnostic().code());
    }

    private static Stm32SignatureMatchReport match(Stm32SignatureContext context,
            Stm32SignaturePack pack) throws Exception {
        return Stm32SignatureMatcher.match(context, pack, ParserLimits.defaults(),
            CancellationToken.none());
    }
}
