package io.github.rezabakhshi.embedra.analyzers.leads.scanner;

import io.github.rezabakhshi.embedra.analyzers.leads.HeuristicFactor;
import io.github.rezabakhshi.embedra.analyzers.leads.LeadCategory;
import io.github.rezabakhshi.embedra.analyzers.leads.LeadConfidence;
import io.github.rezabakhshi.embedra.analyzers.leads.LeadSeverity;
import io.github.rezabakhshi.embedra.analyzers.leads.SecurityLead;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Scans for candidate OTA update endpoints, firmware download URLs, and OTA handler routines (AN-005).
 */
public final class OtaLeadScanner {

    private static final Pattern OTA_URL_PATTERN = Pattern.compile(
            "(?i)^(?:https?|tftp|ftp)://[^\\s\"'<>]+"
                    + "(?:/ota|/update|/firmware|/fota|/upgrade|\\.bin|\\.hex|\\.uf2|\\.pkg).*$");

    private static final Pattern OTA_PATH_PATTERN = Pattern.compile(
            "(?i)^/(?:api/v\\d+/)?(?:ota|update|firmware|fota|upgrade)(?:/[^\\s\"'<>]*)?$");

    private static final Pattern OTA_MQTT_TOPIC_PATTERN = Pattern.compile(
            "(?i)^[A-Za-z0-9_#+$/-]+/(?:ota|firmware/update|update|fota)(?:/[A-Za-z0-9_#+$/-]+)?$");

    private static final Pattern FIRMWARE_FILENAME_PATTERN = Pattern.compile(
            "(?i)^[A-Za-z0-9_.-]+\\.(?:bin|hex|uf2|pkg)$");

    private static final Set<String> KNOWN_OTA_SYMBOLS = Set.of(
            "esp_ota_begin", "esp_ota_write", "esp_ota_end", "esp_https_ota",
            "bootloader_common_ota_select", "esp_ota_set_boot_partition",
            "hal_flash_program", "pico_flash_write", "stm32_dfu", "stm32_iap",
            "fota_start", "ota_update_task", "ota_download_firmware");

    public OtaLeadScanner() {
    }

    /**
     * Scans strings and symbols for candidate OTA leads.
     */
    public List<SecurityLead> scan(
            Map<Long, String> stringTable,
            Map<Long, String> symbolMap,
            ParserLimits limits,
            CancellationToken token) throws DiagnosticException {
        Objects.requireNonNull(stringTable, "stringTable must not be null");
        Objects.requireNonNull(symbolMap, "symbolMap must not be null");
        Objects.requireNonNull(limits, "limits must not be null");

        List<SecurityLead> leads = new ArrayList<>();
        int leadCounter = 1;

        // Check for presence of OTA symbols
        String detectedOtaSymbol = null;
        long otaSymbolAddr = 0;
        for (Map.Entry<Long, String> sym : symbolMap.entrySet()) {
            String lower = sym.getValue().toLowerCase(Locale.ROOT);
            for (String known : KNOWN_OTA_SYMBOLS) {
                if (lower.contains(known)) {
                    detectedOtaSymbol = sym.getValue();
                    otaSymbolAddr = sym.getKey();
                    break;
                }
            }
            if (detectedOtaSymbol != null) {
                break;
            }
        }

        // If OTA API symbol exists, emit lead for the symbol reference
        if (detectedOtaSymbol != null) {
            List<HeuristicFactor> factors = List.of(
                    HeuristicFactor.of("OTA_API_SYMBOL",
                            "Binary references explicit OTA firmware update API: " + detectedOtaSymbol, 0.50));
            String leadId = String.format("LEAD-OTA-%04d", leadCounter++);
            String desc = String.format("Candidate OTA handler function at 0x%X: %s",
                    otaSymbolAddr, detectedOtaSymbol);
            Map<String, String> attrs = Map.of(
                    "otaSymbol", detectedOtaSymbol,
                    "symbolAddress", "0x" + Long.toHexString(otaSymbolAddr));

            leads.add(new SecurityLead(
                    leadId,
                    LeadCategory.OTA_ENDPOINT,
                    LeadConfidence.HIGH,
                    0.80,
                    LeadSeverity.HIGH,
                    otaSymbolAddr,
                    detectedOtaSymbol,
                    detectedOtaSymbol,
                    desc,
                    factors,
                    attrs,
                    false));
        }

        // Scan strings for URLs, paths, MQTT topics, and firmware filenames
        for (Map.Entry<Long, String> entry : stringTable.entrySet()) {
            if (token != null && token.isCancellationRequested()) {
                token.throwIfCancellationRequested();
            }
            if (leads.size() >= limits.maxObjects()) {
                break;
            }

            long strAddr = entry.getKey();
            String raw = entry.getValue().trim();

            boolean isUrl = OTA_URL_PATTERN.matcher(raw).matches();
            boolean isPath = !isUrl && OTA_PATH_PATTERN.matcher(raw).matches();
            boolean isMqtt = !isUrl && !isPath && OTA_MQTT_TOPIC_PATTERN.matcher(raw).matches();
            boolean isFilename = !isUrl && !isPath && !isMqtt && FIRMWARE_FILENAME_PATTERN.matcher(raw).matches()
                    && (raw.toLowerCase(Locale.ROOT).contains("ota")
                    || raw.toLowerCase(Locale.ROOT).contains("firmware")
                    || raw.toLowerCase(Locale.ROOT).contains("update"));

            if (isUrl || isPath || isMqtt || isFilename) {
                List<HeuristicFactor> factors = new ArrayList<>();
                double score = 0.40;

                if (isUrl) {
                    factors.add(HeuristicFactor.of("OTA_URL_PATTERN",
                            "URL endpoint specifies remote firmware update path or image file", 0.50));
                    score += 0.50;
                } else if (isPath) {
                    factors.add(HeuristicFactor.of("OTA_ENDPOINT_PATH",
                            "HTTP URI path targets firmware update service endpoint", 0.40));
                    score += 0.40;
                } else if (isMqtt) {
                    factors.add(HeuristicFactor.of("OTA_MQTT_TOPIC",
                            "MQTT topic targets over-the-air firmware distribution channel", 0.40));
                    score += 0.40;
                } else {
                    factors.add(HeuristicFactor.of("FIRMWARE_IMAGE_FILENAME",
                            "Firmware update image filename referenced in data", 0.30));
                    score += 0.30;
                }

                if (detectedOtaSymbol != null) {
                    factors.add(HeuristicFactor.of("CORROBORATED_BY_OTA_API",
                            "Corroborated by firmware update API symbol in binary (" + detectedOtaSymbol + ")", 0.25));
                    score += 0.25;
                }

                double normalizedScore = Math.min(1.0, score);
                LeadConfidence conf = LeadConfidence.fromScore(normalizedScore);
                LeadSeverity sev = isUrl || isMqtt ? LeadSeverity.HIGH : LeadSeverity.MEDIUM;

                String leadId = String.format("LEAD-OTA-%04d", leadCounter++);
                String desc = String.format("Candidate OTA update endpoint at 0x%X: \"%s\"%s",
                        strAddr, raw,
                        detectedOtaSymbol != null ? " (corroborated by " + detectedOtaSymbol + ")" : "");

                Map<String, String> attrs = new HashMap<>();
                attrs.put("endpointString", raw);
                if (detectedOtaSymbol != null) {
                    attrs.put("corroboratingSymbol", detectedOtaSymbol);
                }

                leads.add(new SecurityLead(
                        leadId,
                        LeadCategory.OTA_ENDPOINT,
                        conf,
                        normalizedScore,
                        sev,
                        strAddr,
                        detectedOtaSymbol,
                        raw,
                        desc,
                        factors,
                        attrs,
                        false));
            }
        }

        return List.copyOf(leads);
    }
}
