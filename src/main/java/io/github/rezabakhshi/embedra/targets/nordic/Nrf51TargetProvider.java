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
 * Pure target provider for Nordic Semiconductor nRF51 series (ARM Cortex-M0).
 */
public final class Nrf51TargetProvider extends AbstractNordicTargetProvider {

    public static final String PROVIDER_ID = "nordic.nrf51";

    public static final String SERIES = "nRF51";

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
            "ARM:LE:32:v6M",
            "default",
            "ARM",
            32,
            2,
            "LITTLE_ENDIAN",
            List.of(new Evidence(
                EvidenceKind.DOCUMENTED_FIELD,
                "nrf51-core",
                "Nordic Semiconductor nRF51 ARM Cortex-M0 (ARMv6-M)"))
        );
    }

    @Override
    public SupportDecision supports(NordicPartRecord part) {
        if (part != null && SERIES.equalsIgnoreCase(part.series())) {
            return new SupportDecision(
                true,
                Optional.of(part.exactPart()),
                "Exact nRF51 part supported by " + PROVIDER_ID,
                List.of(new Evidence(
                    EvidenceKind.DOCUMENTED_FIELD,
                    "nrf51-series",
                    "Part belongs to nRF51 series"))
            );
        }
        return new SupportDecision(
            false,
            Optional.empty(),
            part == null ? "Null part" : "Part " + part.exactPart() + " is not an nRF51 device",
            List.of()
        );
    }
}
