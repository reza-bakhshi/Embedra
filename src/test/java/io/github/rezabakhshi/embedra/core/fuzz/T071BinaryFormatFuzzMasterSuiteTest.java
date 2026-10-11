package io.github.rezabakhshi.embedra.core.fuzz;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * T071 Master Fuzz Suite: Verifies at least 10,000 deterministic malformed inputs
 * per implemented binary format without crash, hang, uncontrolled allocation,
 * or committed partial program state.
 */
public class T071BinaryFormatFuzzMasterSuiteTest {

    public static final int REQUIRED_MINIMUM_CASES_PER_FORMAT = 10_000;

    @Test
    void verifyAllImplementedBinaryFormatsPassTenThousandMalformedCampaign() {
        Map<String, Integer> formatCaseCounts = new LinkedHashMap<>();
        formatCaseCounts.put("ESP32 Application Image (0xE9)", Esp32BinaryFormatFuzzTest.CAMPAIGN_CASES);
        formatCaseCounts.put("ESP8266 Firmware Image (v1 & v2)", Esp8266BinaryFormatFuzzTest.CAMPAIGN_CASES);
        formatCaseCounts.put("Raspberry Pi UF2 (RP2040 & RP2350)", RpUf2BinaryFormatFuzzTest.CAMPAIGN_CASES);
        formatCaseCounts.put("STM32 DfuSe Binary", Stm32DfuBinaryFormatFuzzTest.CAMPAIGN_CASES);
        formatCaseCounts.put("STM32 Raw Binary Vector Discovery",
                Stm32VectorDiscoveryBinaryFormatFuzzTest.CAMPAIGN_CASES);
        formatCaseCounts.put("ESP Full-Flash Partition Table (0xAA50)",
                EspPartitionTableBinaryFormatFuzzTest.CAMPAIGN_CASES);
        formatCaseCounts.put("Raspberry Pi Boot Metadata (Boot2 & ImageDef)",
                RpBootMetadataBinaryFormatFuzzTest.CAMPAIGN_CASES);

        assertEquals(7, formatCaseCounts.size(), "Must cover all 7 implemented binary formats");

        int totalCases = 0;
        for (Map.Entry<String, Integer> entry : formatCaseCounts.entrySet()) {
            String formatName = entry.getKey();
            int cases = entry.getValue();
            assertTrue(cases >= REQUIRED_MINIMUM_CASES_PER_FORMAT,
                    formatName + " must execute at least 10,000 malformed inputs: " + cases);
            totalCases += cases;
        }

        assertTrue(totalCases >= 70_000,
                "Total deterministic malformed cases across all binary formats must be at least 70,000: " + totalCases);
    }

    @Test
    void verifyEndToEndCampaignExecutionSummary() throws Exception {
        byte[] esp32 = getClass().getResourceAsStream(
                "/fixtures/esp32s3/esp32s3-freestanding-minimal.bin").readAllBytes();
        var r1 = Esp32BinaryFormatFuzzTest.runCampaign(
                esp32, Esp32BinaryFormatFuzzTest.SEED, Esp32BinaryFormatFuzzTest.CAMPAIGN_CASES);
        assertEquals(10_000, r1.totalCases());
        assertTrue(r1.rejectedCount() > 0);

        byte[] esp8266v1 = getClass().getResourceAsStream(
                "/fixtures/esp8266/esp8266-freestanding-v1-0x00000.bin").readAllBytes();
        byte[] esp8266v2 = getClass().getResourceAsStream(
                "/fixtures/esp8266/esp8266-freestanding-v2-0x01000.bin").readAllBytes();
        var r2 = Esp8266BinaryFormatFuzzTest.runCampaign(
                esp8266v1, esp8266v2, Esp8266BinaryFormatFuzzTest.SEED, Esp8266BinaryFormatFuzzTest.CAMPAIGN_CASES);
        assertEquals(10_000, r2.totalCases());
        assertTrue(r2.rejectedCount() > 0);

        byte[] rpUf2 = getClass().getResourceAsStream(
                "/fixtures/rp/rp2040-pico-blinky.uf2").readAllBytes();
        var r3 = RpUf2BinaryFormatFuzzTest.runCampaign(
                rpUf2, RpUf2BinaryFormatFuzzTest.SEED, RpUf2BinaryFormatFuzzTest.CAMPAIGN_CASES);
        assertEquals(10_000, r3.totalCases());
        assertTrue(r3.rejectedCount() > 0);

        var r4 = Stm32DfuBinaryFormatFuzzTest.runCampaign(
                Stm32DfuBinaryFormatFuzzTest.createValidDfu(),
                Stm32DfuBinaryFormatFuzzTest.SEED, Stm32DfuBinaryFormatFuzzTest.CAMPAIGN_CASES);
        assertEquals(10_000, r4.totalCases());
        assertTrue(r4.rejectedCount() > 0);

        var r5 = Stm32VectorDiscoveryBinaryFormatFuzzTest.runCampaign(
                Stm32VectorDiscoveryBinaryFormatFuzzTest.createValidVectorTable(),
                Stm32VectorDiscoveryBinaryFormatFuzzTest.SEED,
                Stm32VectorDiscoveryBinaryFormatFuzzTest.CAMPAIGN_CASES);
        assertEquals(10_000, r5.totalCases());
        assertTrue(r5.noCandidatesCount() > 0);

        byte[] part = getClass().getResourceAsStream(
                "/fixtures/esp32s3/full-flash/default-factory.bin").readAllBytes();
        var r6 = EspPartitionTableBinaryFormatFuzzTest.runCampaign(
                part, EspPartitionTableBinaryFormatFuzzTest.SEED,
                EspPartitionTableBinaryFormatFuzzTest.CAMPAIGN_CASES);
        assertEquals(10_000, r6.totalCases());
        assertTrue(r6.rejectedCount() > 0);

        byte[] b2 = RpBootMetadataBinaryFormatFuzzTest.createValidRp2040Boot2();
        byte[] idef = RpBootMetadataBinaryFormatFuzzTest.createValidRp2350ImageDef();
        var r7 = RpBootMetadataBinaryFormatFuzzTest.runCampaign(
                b2, idef, RpBootMetadataBinaryFormatFuzzTest.SEED,
                RpBootMetadataBinaryFormatFuzzTest.CAMPAIGN_CASES);
        assertEquals(10_000, r7.totalCases());
        assertTrue(r7.rejectedCount() > 0);
    }
}
