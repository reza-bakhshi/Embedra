package io.github.rezabakhshi.embedra.analyzers.rp;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.core.model.Confidence;
import io.github.rezabakhshi.embedra.core.model.Evidence;
import io.github.rezabakhshi.embedra.core.model.EvidenceKind;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Pure detector identifying Infineon CYW43439 wireless driver signatures, bus wrappers, and firmware markers.
 */
public final class RpCyw43Detector {

    private static final Set<String> KNOWN_APIS = Set.of(
            "cyw43_arch_init", "cyw43_arch_init_with_country", "cyw43_arch_enable_sta_mode",
            "cyw43_arch_enable_ap_mode", "cyw43_arch_wifi_connect_blocking", "cyw43_arch_wifi_connect_async",
            "cyw43_arch_poll", "cyw43_driver_init", "cyw43_wifi_set_up",
            "cyw43_spi_init", "cyw43_pio_init", "cyw43_spi_pio_init");

    private static final Set<String> COUNTRY_CODES = Set.of("WW", "US", "GB", "EU", "JP", "DE", "FR", "CA", "AU");

    public RpCyw43Match detect(
            RpAnalysisContext context,
            ParserLimits limits,
            CancellationToken token) throws DiagnosticException {
        Objects.requireNonNull(context, "context must not be null");
        Objects.requireNonNull(limits, "limits must not be null");
        Objects.requireNonNull(token, "token must not be null");

        token.throwIfCancellationRequested();

        String busInterface = null;
        boolean firmwareBlobPresent = false;
        Set<String> matchedCountries = new LinkedHashSet<>();
        List<String> matchedApis = new ArrayList<>();
        List<Evidence> evidence = new ArrayList<>();

        for (String sym : context.symbols()) {
            token.throwIfCancellationRequested();
            if (KNOWN_APIS.contains(sym)) {
                matchedApis.add(sym);
                if (sym.contains("pio")) {
                    busInterface = "PIO";
                } else if (sym.contains("spi") && busInterface == null) {
                    busInterface = "SPI";
                }
            }
        }

        for (String str : context.strings()) {
            token.throwIfCancellationRequested();
            if (KNOWN_APIS.contains(str) && !matchedApis.contains(str)) {
                matchedApis.add(str);
                if (str.contains("pio")) {
                    busInterface = "PIO";
                } else if (str.contains("spi") && busInterface == null) {
                    busInterface = "SPI";
                }
            }

            if (str.contains("CYW43439") || str.contains("cyw43439")) {
                evidence.add(new Evidence(
                        EvidenceKind.DOCUMENTED_FIELD,
                        "CYW43439 Hardware Marker",
                        "Identified string: " + str));
            } else if (str.contains("cyw43") || str.contains("CYW43")) {
                evidence.add(new Evidence(
                        EvidenceKind.HEURISTIC,
                        "CYW43 Driver Marker",
                        "Found string: " + str));
            }

            if (str.contains("43439A0") || str.contains("fmac_fw") || str.contains("clm_blob")) {
                firmwareBlobPresent = true;
                evidence.add(new Evidence(
                        EvidenceKind.DOCUMENTED_FIELD,
                        "CYW43439 Firmware Blob",
                        "Identified firmware asset: " + str));
            }

            if (str.startsWith("CYW43_COUNTRY_")) {
                String code = str.substring("CYW43_COUNTRY_".length());
                if (!code.isBlank()) {
                    matchedCountries.add(code);
                }
            } else if (COUNTRY_CODES.contains(str)) {
                matchedCountries.add(str);
            }
        }

        if (!matchedApis.isEmpty()) {
            evidence.add(new Evidence(
                    EvidenceKind.EXACT_SIGNATURE_MATCH,
                    "CYW43 Driver APIs",
                    "Identified CYW43 wireless APIs: " + String.join(", ", matchedApis)));
        }

        if (busInterface != null) {
            evidence.add(new Evidence(
                    EvidenceKind.DOCUMENTED_FIELD,
                    "CYW43 Bus Interface",
                    "Identified " + busInterface + " bus control wrapper"));
        }

        boolean detected = !matchedApis.isEmpty() || !evidence.isEmpty();
        if (!detected) {
            return RpCyw43Match.notDetected();
        }

        Confidence confidence;
        if (!matchedApis.isEmpty() && firmwareBlobPresent) {
            confidence = Confidence.VERIFIED;
        } else if (!matchedApis.isEmpty() || firmwareBlobPresent) {
            confidence = Confidence.DERIVED;
        } else {
            confidence = Confidence.HEURISTIC;
        }

        return new RpCyw43Match(
                true,
                "Infineon CYW43439",
                Optional.ofNullable(busInterface),
                firmwareBlobPresent,
                List.copyOf(matchedCountries),
                matchedApis,
                confidence,
                evidence);
    }
}
