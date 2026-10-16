package io.github.rezabakhshi.embedra.targets.atmel;

import io.github.rezabakhshi.embedra.core.model.Evidence;
import io.github.rezabakhshi.embedra.core.model.EvidenceKind;
import io.github.rezabakhshi.embedra.targets.LanguageSelection;
import io.github.rezabakhshi.embedra.targets.SupportDecision;
import io.github.rezabakhshi.embedra.targets.atmel.catalog.AtmelPartRecord;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Target provider for Microchip SAME / SAMS / SAMV / SAM3 ARM Cortex-M7 and Cortex-M3 microcontrollers.
 */
public final class SameTargetProvider extends AbstractAtmelTargetProvider {

    public static final String PROVIDER_ID = "atmel-same";

    public static final String SERIES = "SAME";

    @Override
    public String providerId() {
        return PROVIDER_ID;
    }

    @Override
    public String series() {
        return SERIES;
    }

    @Override
    public String family() {
        return "SAM";
    }

    @Override
    public SupportDecision supports(AtmelPartRecord part) {
        if (part != null && "SAM".equalsIgnoreCase(part.family()) && SERIES.equalsIgnoreCase(part.series())) {
            return new SupportDecision(
                true,
                Optional.of(part.exactPart()),
                "Exact SAME part supported by " + PROVIDER_ID,
                List.of(new Evidence(
                    EvidenceKind.DOCUMENTED_FIELD,
                    "same-series",
                    "Part belongs to SAME series"))
            );
        }
        return new SupportDecision(
            false,
            Optional.empty(),
            part == null ? "Null part" : "Part " + part.exactPart() + " is not a SAME device",
            List.of()
        );
    }

    @Override
    public LanguageSelection selectLanguage(AtmelPartRecord part) {
        Objects.requireNonNull(part, "part must not be null");
        String langId = part.ghidraLanguage();
        String isa = langId.contains("v7M") ? "ARMv7-M" : "ARMv7E-M";
        return new LanguageSelection(
            langId,
            "default",
            isa,
            32,
            2,
            "little",
            List.of(new Evidence(
                EvidenceKind.DERIVED_RULE,
                "same-language-selection",
                "Selected " + langId + " for " + part.exactPart()))
        );
    }
}
