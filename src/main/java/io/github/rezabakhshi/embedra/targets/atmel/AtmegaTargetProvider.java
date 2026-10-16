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
 * Target provider for classic Atmel megaAVR microcontrollers.
 */
public final class AtmegaTargetProvider extends AbstractAtmelTargetProvider {

    public static final String PROVIDER_ID = "atmel-atmega";

    public static final String SERIES = "ATmega";

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
        return "AVR";
    }

    @Override
    public SupportDecision supports(AtmelPartRecord part) {
        if (part != null && "AVR".equalsIgnoreCase(part.family()) && SERIES.equalsIgnoreCase(part.series())) {
            return new SupportDecision(
                true,
                Optional.of(part.exactPart()),
                "Exact ATmega part supported by " + PROVIDER_ID,
                List.of(new Evidence(
                    EvidenceKind.DOCUMENTED_FIELD,
                    "atmega-series",
                    "Part belongs to ATmega series"))
            );
        }
        return new SupportDecision(
            false,
            Optional.empty(),
            part == null ? "Null part" : "Part " + part.exactPart() + " is not an ATmega device",
            List.of()
        );
    }

    @Override
    public LanguageSelection selectLanguage(AtmelPartRecord part) {
        Objects.requireNonNull(part, "part must not be null");
        String langId = part.ghidraLanguage();
        int addrBits = langId.contains("24") ? 24 : 16;
        return new LanguageSelection(
            langId,
            "default",
            "AVR8",
            addrBits,
            2,
            "little",
            List.of(new Evidence(
                EvidenceKind.DERIVED_RULE,
                "atmega-language-selection",
                "Selected " + langId + " for " + part.exactPart()))
        );
    }
}
