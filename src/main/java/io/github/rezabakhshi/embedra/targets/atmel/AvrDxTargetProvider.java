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
 * Target provider for modern Microchip AVR-DA / AVR-DB / AVR-DD microcontrollers.
 */
public final class AvrDxTargetProvider extends AbstractAtmelTargetProvider {

    public static final String PROVIDER_ID = "atmel-avr-dx";

    public static final String SERIES = "AVR-Dx";

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
                "Exact AVR-Dx part supported by " + PROVIDER_ID,
                List.of(new Evidence(
                    EvidenceKind.DOCUMENTED_FIELD,
                    "avr-dx-series",
                    "Part belongs to AVR-Dx series"))
            );
        }
        return new SupportDecision(
            false,
            Optional.empty(),
            part == null ? "Null part" : "Part " + part.exactPart() + " is not an AVR-Dx device",
            List.of()
        );
    }

    @Override
    public LanguageSelection selectLanguage(AtmelPartRecord part) {
        Objects.requireNonNull(part, "part must not be null");
        String langId = part.ghidraLanguage();
        return new LanguageSelection(
            langId,
            "default",
            "AVR8X",
            24,
            2,
            "little",
            List.of(new Evidence(
                EvidenceKind.DERIVED_RULE,
                "avr-dx-language-selection",
                "Selected " + langId + " for " + part.exactPart()))
        );
    }
}
