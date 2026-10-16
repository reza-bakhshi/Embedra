package io.github.rezabakhshi.embedra.targets.stm8;

import io.github.rezabakhshi.embedra.core.model.Evidence;
import io.github.rezabakhshi.embedra.core.model.EvidenceKind;
import io.github.rezabakhshi.embedra.targets.SupportDecision;
import io.github.rezabakhshi.embedra.targets.stm8.catalog.Stm8PartRecord;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Pure target provider for the STM8L ultra-low-power 8-bit microcontroller family (RM0031).
 */
public final class Stm8lTargetProvider extends AbstractStm8TargetProvider {

    public static final String PROVIDER_ID = "io.github.rezabakhshi.embedra.targets.stm8.stm8l";

    public static final String FAMILY = "STM8L";

    @Override
    public String providerId() {
        return PROVIDER_ID;
    }

    @Override
    public String family() {
        return FAMILY;
    }

    @Override
    public SupportDecision supports(Stm8PartRecord part) {
        Objects.requireNonNull(part, "part must not be null");
        if (FAMILY.equalsIgnoreCase(part.family())) {
            return new SupportDecision(
                true,
                Optional.of(part.exactPart()),
                "Exact STM8L part supported by " + PROVIDER_ID,
                List.of(new Evidence(
                    EvidenceKind.DOCUMENTED_FIELD,
                    "stm8l-family",
                    "Part belongs to STM8L ultra-low-power family: " + part.subfamily()))
            );
        }
        return new SupportDecision(
            false,
            Optional.empty(),
            "Part " + part.exactPart() + " is not an STM8L device (family: " + part.family() + ")",
            List.of()
        );
    }
}
