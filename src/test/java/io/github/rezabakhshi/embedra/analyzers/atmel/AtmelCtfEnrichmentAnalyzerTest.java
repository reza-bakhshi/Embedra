package io.github.rezabakhshi.embedra.analyzers.atmel;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.analyzers.ctf.CtfEntity;
import io.github.rezabakhshi.embedra.analyzers.ctf.CtfEntityType;
import io.github.rezabakhshi.embedra.analyzers.strings.stack.InstructionArch;
import io.github.rezabakhshi.embedra.analyzers.strings.stack.StackInstruction;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class AtmelCtfEnrichmentAnalyzerTest {

    @Test
    void recoversCtfEntitiesAndSignaturesFromAvrFirmware() throws Exception {
        AtmelCtfEnrichmentAnalyzer analyzer = new AtmelCtfEnrichmentAnalyzer();

        byte[] flash = new byte[1024];
        long flashBase = 0x00000000L;

        // At 0x00000100: pinMode pattern
        byte[] avrPinMode = new byte[] {
            (byte) 0x08, (byte) 0x95, (byte) 0x88, (byte) 0x23, (byte) 0x99, (byte) 0x27, (byte) 0x80, (byte) 0x91
        };
        System.arraycopy(avrPinMode, 0, flash, 0x100, avrPinMode.length);

        // At 0x00000180: Command string "auth_token"
        byte[] cmdBytes = "auth_token\0".getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(cmdBytes, 0, flash, 0x180, cmdBytes.length);

        // At 0x00000200: Flag
        byte[] flagBytes = "flag{atmel_atmega328p_arduino_ctf}\0".getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(flagBytes, 0, flash, 0x200, flagBytes.length);

        // At 0x00000280: URL
        byte[] urlBytes = "https://microchip.internal/firmware/ota\0".getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(urlBytes, 0, flash, 0x280, urlBytes.length);

        // At 0x00000300: 16-bit command table (strPtr = 0x0180, fnPtr = 0x0100)
        ByteBuffer bb = ByteBuffer.wrap(flash).order(ByteOrder.LITTLE_ENDIAN);
        bb.putShort(0x300, (short) 0x0180);
        bb.putShort(0x302, (short) 0x0100);

        AtmelSignatureContext sigContext = new AtmelSignatureContext(
                "ATmega328P",
                "ATmega",
                "AVR8",
                Optional.of("ANY"),
                Optional.empty(),
                List.of(new AtmelFunctionBytes(0x00000100L, avrPinMode)));

        Map<Long, String> symbolMap = new HashMap<>();
        symbolMap.put(0x00000100L, "pinMode");

        // Stack instructions for AVR8
        List<StackInstruction> avrInstrs = List.of(
                StackInstruction.avr8(0x110, "ldi", "r24", "0x50"),
                StackInstruction.avr8(0x112, "std", "Y+1", "r24"),
                StackInstruction.avr8(0x114, "ldi", "r24", "0x41"),
                StackInstruction.avr8(0x116, "std", "Y+2", "r24"),
                StackInstruction.avr8(0x118, "ldi", "r24", "0x53"),
                StackInstruction.avr8(0x11A, "std", "Y+3", "r24"),
                StackInstruction.avr8(0x11C, "ldi", "r24", "0x53"),
                StackInstruction.avr8(0x11E, "std", "Y+4", "r24"),
                StackInstruction.avr8(0x120, "ldi", "r24", "0x00"),
                StackInstruction.avr8(0x122, "std", "Y+5", "r24")
        );

        AtmelCtfEnrichmentContext context = new AtmelCtfEnrichmentContext(
                sigContext,
                flash,
                flashBase,
                symbolMap,
                Map.of(0x00000100L, avrInstrs));

        AtmelCtfEnrichmentReport report = analyzer.analyze(
                context,
                AtmelSignaturePack.builtin(),
                ParserLimits.defaults(),
                CancellationToken.none());

        assertNotNull(report);
        assertEquals(1, report.signatureReport().matches().size());
        assertEquals("pinMode", report.signatureReport().matches().get(0).functionName());

        assertFalse(report.extractedStrings().isEmpty());

        boolean flagFound = false;
        boolean urlFound = false;
        for (CtfEntity entity : report.ctfEntities()) {
            if (entity.type() == CtfEntityType.FLAG && entity.value().contains("atmel_atmega328p_arduino_ctf")) {
                flagFound = true;
            }
            if (entity.type() == CtfEntityType.URL && entity.value().contains("microchip.internal")) {
                urlFound = true;
            }
        }
        assertTrue(flagFound, "Expected CTF flag to be recovered");
        assertTrue(urlFound, "Expected URL to be recovered");

        // Recovered stack string "PASS"
        assertFalse(report.stackStrings().isEmpty());
        assertTrue(report.stackStrings().stream().anyMatch(ss -> ss.content().equals("PASS")));
    }

    @Test
    void recoversCtfEntitiesAndSignaturesFromSamFirmware() throws Exception {
        AtmelCtfEnrichmentAnalyzer analyzer = new AtmelCtfEnrichmentAnalyzer();

        byte[] flash = new byte[1024];
        long flashBase = 0x00000000L;

        // At 0x00000100: delay_ms
        byte[] samDelayMs = new byte[] {
            (byte) 0x10, (byte) 0xB5, (byte) 0x4F, (byte) 0xF4, (byte) 0x7A, (byte) 0x71, (byte) 0x01, (byte) 0xFB
        };
        System.arraycopy(samDelayMs, 0, flash, 0x100, samDelayMs.length);

        // At 0x00000180: Command string "auth_token"
        byte[] cmdBytes = "auth_token\0".getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(cmdBytes, 0, flash, 0x180, cmdBytes.length);

        // At 0x00000200: Flag
        byte[] flagBytes = "flag{atmel_samd21_asf_ctf_token}\0".getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(flagBytes, 0, flash, 0x200, flagBytes.length);

        // At 0x00000300: 32-bit command table (strPtr = 0x00000180, fnPtr = 0x00000101)
        ByteBuffer bb = ByteBuffer.wrap(flash).order(ByteOrder.LITTLE_ENDIAN);
        bb.putInt(0x300, 0x00000180);
        bb.putInt(0x304, 0x00000101);

        AtmelSignatureContext sigContext = new AtmelSignatureContext(
                "SAMD21G18A",
                "SAMD",
                "ARM_THUMB",
                Optional.of("ANY"),
                Optional.empty(),
                List.of(new AtmelFunctionBytes(0x00000100L, samDelayMs)));

        Map<Long, String> symbolMap = new HashMap<>();
        symbolMap.put(0x00000100L, "delay_ms");

        AtmelCtfEnrichmentContext context = new AtmelCtfEnrichmentContext(
                sigContext,
                flash,
                flashBase,
                symbolMap,
                Map.of());

        AtmelCtfEnrichmentReport report = analyzer.analyze(
                context,
                AtmelSignaturePack.builtin(),
                ParserLimits.defaults(),
                CancellationToken.none());

        assertNotNull(report);
        assertEquals(1, report.signatureReport().matches().size());
        assertEquals("delay_ms", report.signatureReport().matches().get(0).functionName());

        boolean flagFound = false;
        for (CtfEntity entity : report.ctfEntities()) {
            if (entity.type() == CtfEntityType.FLAG && entity.value().contains("atmel_samd21_asf_ctf_token")) {
                flagFound = true;
            }
        }
        assertTrue(flagFound, "Expected SAM CTF flag to be recovered");
    }

    @Test
    void rejectsExcessiveFlashPayload() {
        AtmelCtfEnrichmentAnalyzer analyzer = new AtmelCtfEnrichmentAnalyzer();
        ParserLimits limits = new ParserLimits(
                100, 100, 100, 100, 10, java.time.Duration.ofSeconds(5));

        AtmelSignatureContext sigContext = new AtmelSignatureContext(
                "ATmega328P", "ATmega", "AVR8", Optional.empty(), Optional.empty(), List.of());
        AtmelCtfEnrichmentContext context = new AtmelCtfEnrichmentContext(
                sigContext, new byte[200], 0L, Map.of(), Map.of());

        assertThrows(DiagnosticException.class, () ->
                analyzer.analyze(context, AtmelSignaturePack.builtin(), limits, CancellationToken.none()));
    }
}
