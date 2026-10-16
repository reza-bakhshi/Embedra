package io.github.rezabakhshi.embedra.targets.nordic;

import io.github.rezabakhshi.embedra.core.model.Evidence;
import io.github.rezabakhshi.embedra.core.model.EvidenceKind;
import io.github.rezabakhshi.embedra.targets.LanguageSelection;
import io.github.rezabakhshi.embedra.targets.SupportDecision;
import io.github.rezabakhshi.embedra.targets.nordic.catalog.NordicPartRecord;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Pure target provider for Nordic Semiconductor nRF91 series (ARM Cortex-M33 Cellular / TrustZone).
 */
public final class Nrf91TargetProvider extends AbstractNordicTargetProvider {

    public static final String PROVIDER_ID = "nordic.nrf91";

    public static final String SERIES = "nRF91";

    @Override
    public String providerId() {
        return PROVIDER_ID;
    }

    @Override
    public String series() {
        return SERIES;
    }

    @Override
    public LanguageSelection selectLanguage(NordicPartRecord part) {
        Objects.requireNonNull(part, "part must not be null");
        return new LanguageSelection(
            "ARM:LE:32:v8M",
            "default",
            "ARM",
            32,
            2,
            "LITTLE_ENDIAN",
            List.of(new Evidence(
                EvidenceKind.DOCUMENTED_FIELD,
                "nrf91-core",
                "Nordic Semiconductor nRF91 ARM Cortex-M33 TrustZone (ARMv8-M)"))
        );
    }

    @Override
    public SupportDecision supports(NordicPartRecord part) {
        if (part != null && SERIES.equalsIgnoreCase(part.series())) {
            return new SupportDecision(
                true,
                Optional.of(part.exactPart()),
                "Exact nRF91 part supported by " + PROVIDER_ID,
                List.of(new Evidence(
                    EvidenceKind.DOCUMENTED_FIELD,
                    "nrf91-series",
                    "Part belongs to nRF91 series"))
            );
        }
        return new SupportDecision(
            false,
            Optional.empty(),
            part == null ? "Null part" : "Part " + part.exactPart() + " is not an nRF91 device",
            List.of()
        );
    }
}
