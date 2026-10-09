package io.github.rezabakhshi.embedra.analyzers.leads;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.analyzers.leads.scanner.OtaLeadScanner;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class OtaLeadScannerTest {

    @Test
    void detectsOtaUrlAndApiSymbolCorroboration() throws Exception {
        OtaLeadScanner scanner = new OtaLeadScanner();

        Map<Long, String> stringTable = Map.of(
                0x1000L, "https://updates.example.com/ota/firmware.bin",
                0x1050L, "http://api.weather.com/v1/forecast");

        Map<Long, String> symbolMap = Map.of(
                0x8000L, "esp_https_ota");

        List<SecurityLead> leads = scanner.scan(
                stringTable,
                symbolMap,
                ParserLimits.defaults(),
                CancellationToken.none());

        // Should detect the OTA symbol handler lead + the OTA URL lead
        assertEquals(2, leads.size());

        SecurityLead urlLead = leads.stream()
                .filter(l -> l.target().contains("firmware.bin"))
                .findFirst()
                .orElseThrow();

        assertEquals(LeadCategory.OTA_ENDPOINT, urlLead.category());
        assertEquals(0x1000L, urlLead.address());
        assertEquals(LeadConfidence.HIGH, urlLead.confidence());
        assertTrue(urlLead.description().contains("esp_https_ota"));
        assertFalse(urlLead.secret());

        SecurityLead apiLead = leads.stream()
                .filter(l -> l.target().equals("esp_https_ota"))
                .findFirst()
                .orElseThrow();

        assertEquals(0x8000L, apiLead.address());
        assertEquals(LeadCategory.OTA_ENDPOINT, apiLead.category());
    }

    @Test
    void detectsOtaMqttTopicAndApiPath() throws Exception {
        OtaLeadScanner scanner = new OtaLeadScanner();

        Map<Long, String> stringTable = Map.of(
                0x2000L, "devices/factory_node/firmware/update",
                0x2040L, "/api/v1/ota/update",
                0x2080L, "sensors/temperature/living_room");

        Map<Long, String> symbolMap = Map.of();

        List<SecurityLead> leads = scanner.scan(
                stringTable,
                symbolMap,
                ParserLimits.defaults(),
                CancellationToken.none());

        assertEquals(2, leads.size(), "Should discover MQTT topic and REST path");

        assertTrue(leads.stream().anyMatch(l -> l.target().contains("firmware/update")));
        assertTrue(leads.stream().anyMatch(l -> l.target().equals("/api/v1/ota/update")));
    }
}
