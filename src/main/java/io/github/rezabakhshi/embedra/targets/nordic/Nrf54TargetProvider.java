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
 * Pure target provider for Nordic Semiconductor nRF54 series (ARM Cortex-M33 + RISC-V).
 */
public final class Nrf54TargetProvider extends AbstractNordicTargetProvider {

    public static final String PROVIDER_ID = "nordic.nrf54";

    public static final String SERIES = "nRF54";

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
                "nrf54-core",
                "Nordic Semiconductor nRF54 ARM Cortex-M33 (ARMv8-M)"))
        );
    }

    @Override
    public SupportDecision supports(NordicPartRecord part) {
        if (part != null && SERIES.equalsIgnoreCase(part.series())) {
            return new SupportDecision(
                true,
                Optional.of(part.exactPart()),
                "Exact nRF54 part supported by " + PROVIDER_ID,
                List.of(new Evidence(
                    EvidenceKind.DOCUMENTED_FIELD,
                    "nrf54-series",
                    "Part belongs to nRF54 series"))
            );
        }
        return new SupportDecision(
            false,
            Optional.empty(),
            part == null ? "Null part" : "Part " + part.exactPart() + " is not an nRF54 device",
            List.of()
        );
    }
}
