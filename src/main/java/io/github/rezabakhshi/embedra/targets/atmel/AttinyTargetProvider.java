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
 * Target provider for classic Atmel tinyAVR microcontrollers.
 */
public final class AttinyTargetProvider extends AbstractAtmelTargetProvider {

    public static final String PROVIDER_ID = "atmel-attiny";

    public static final String SERIES = "ATtiny";

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
                "Exact ATtiny part supported by " + PROVIDER_ID,
                List.of(new Evidence(
                    EvidenceKind.DOCUMENTED_FIELD,
                    "attiny-series",
                    "Part belongs to ATtiny series"))
            );
        }
        return new SupportDecision(
            false,
            Optional.empty(),
            part == null ? "Null part" : "Part " + part.exactPart() + " is not an ATtiny device",
            List.of()
        );
    }

    @Override
    public LanguageSelection selectLanguage(AtmelPartRecord part) {
        Objects.requireNonNull(part, "part must not be null");
        String langId = part.ghidraLanguage();
        int addrBits = langId.contains("24") ? 24 : 16;
        String isa = langId.contains("xmega") ? "AVR8X" : "AVR8";
        return new LanguageSelection(
            langId,
            "default",
            isa,
            addrBits,
            2,
            "little",
            List.of(new Evidence(
                EvidenceKind.DERIVED_RULE,
                "attiny-language-selection",
                "Selected " + langId + " for " + part.exactPart()))
        );
    }
}
