package io.github.rezabakhshi.embedra.analyzers.nordic;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.analyzers.ctf.CtfEntity;
import io.github.rezabakhshi.embedra.analyzers.ctf.CtfEntityType;
import io.github.rezabakhshi.embedra.analyzers.leads.SecurityLead;
import io.github.rezabakhshi.embedra.analyzers.strings.stack.InstructionArch;
import io.github.rezabakhshi.embedra.analyzers.strings.stack.StackInstruction;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class NordicCtfEnrichmentAnalyzerTest {

    @Test
    void recoversCtfEntitiesAndSignaturesFromNordicFirmware() throws Exception {
        NordicCtfEnrichmentAnalyzer analyzer = new NordicCtfEnrichmentAnalyzer();

        byte[] flash = new byte[1024];
        long flashBase = 0x00026000L;

        // Slot 0 & 1: Cortex-M vector table (Initial SP 0x20004000, Reset Handler 0x00026081)
        ByteBuffer bb = ByteBuffer.wrap(flash).order(ByteOrder.LITTLE_ENDIAN);
        bb.putInt(0, 0x20004000);
        bb.putInt(4, 0x00026081);

        // At 0x00026080 (offset 128): sd_ble_gap_adv_start pattern
        byte[] bleAdvStart = new byte[] {
            0x10, (byte) 0xB5, 0x73, (byte) 0xDF, 0x10, (byte) 0xBD, 0x00, (byte) 0xBF
        };
        System.arraycopy(bleAdvStart, 0, flash, 128, bleAdvStart.length);

        // At 0x00026100 (offset 256): Embed Flag string
        byte[] flagBytes = "flag{nordic_nrf52_ble_crypto_pass}\0".getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(flagBytes, 0, flash, 256, flagBytes.length);

        // At 0x00026140 (offset 320): Embed URL
        byte[] urlBytes = "https://nordicsemi.internal/firmware/ota\0".getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(urlBytes, 0, flash, 320, urlBytes.length);

        // At 0x00026180 (offset 384): Embed Command string "auth_token"
        byte[] cmdBytes = "auth_token\0".getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(cmdBytes, 0, flash, 384, cmdBytes.length);

        // At 0x00026200 (offset 512): Command table with 32-bit pointers:
        // strPtr = 0x00026180, fnPtr = 0x00026081 (Thumb bit set)
        bb.putInt(512, 0x00026180);
        bb.putInt(516, 0x00026081);

        NordicSignatureContext sigContext = new NordicSignatureContext(
                "nRF52840-QIAA",
                "nRF52",
                Optional.of("ANY"),
                Optional.empty(),
                List.of(new NordicFunctionBytes(0x00026080L, bleAdvStart)));

        Map<Long, String> symbolMap = new HashMap<>();
        symbolMap.put(0x00026080L, "Reset_Handler");

        NordicCtfEnrichmentContext context = new NordicCtfEnrichmentContext(
                sigContext,
                flash,
                flashBase,
                symbolMap,
                Map.of());

        NordicCtfEnrichmentReport report = analyzer.analyze(
                context,
                NordicSignaturePack.builtin(),
                ParserLimits.defaults(),
                CancellationToken.none());

        assertNotNull(report);
        assertEquals(1, report.signatureReport().matches().size());
        assertEquals("sd_ble_gap_adv_start", report.signatureReport().matches().get(0).functionName());

        assertFalse(report.extractedStrings().isEmpty());

        // Verify CTF flags discovered
        boolean flagFound = false;
        boolean urlFound = false;
        for (CtfEntity entity : report.ctfEntities()) {
            if (entity.type() == CtfEntityType.FLAG && entity.value().contains("nordic_nrf52_ble_crypto_pass")) {
                flagFound = true;
            }
            if (entity.type() == CtfEntityType.URL && entity.value().contains("nordicsemi.internal")) {
                urlFound = true;
            }
        }
        assertTrue(flagFound, "Expected CTF flag to be recovered");
        assertTrue(urlFound, "Expected URL entity to be recovered");

        assertTrue(report.detectorsRun().contains("nrf5-sdk-signatures"));
        assertTrue(report.detectorsRun().contains("nordic-ctf-entity-scanner"));
    }
}
