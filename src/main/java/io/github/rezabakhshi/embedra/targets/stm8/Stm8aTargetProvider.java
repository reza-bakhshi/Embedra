package io.github.rezabakhshi.embedra.targets.stm8;

import io.github.rezabakhshi.embedra.core.model.Evidence;
import io.github.rezabakhshi.embedra.core.model.EvidenceKind;
import io.github.rezabakhshi.embedra.targets.SupportDecision;
import io.github.rezabakhshi.embedra.targets.stm8.catalog.Stm8PartRecord;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Pure target provider for the STM8A automotive microcontroller family (STM8AF and STM8AL).
 */
public final class Stm8aTargetProvider extends AbstractStm8TargetProvider {

    public static final String PROVIDER_ID = "io.github.rezabakhshi.embedra.targets.stm8.stm8a";

    public static final String FAMILY = "STM8A";

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
        boolean matches = FAMILY.equalsIgnoreCase(part.family())
            || "STM8AF".equalsIgnoreCase(part.family())
            || "STM8AL".equalsIgnoreCase(part.family())
            || part.subfamily().toUpperCase().startsWith("STM8A");

        if (matches) {
            return new SupportDecision(
                true,
                Optional.of(part.exactPart()),
                "Exact STM8A automotive part supported by " + PROVIDER_ID,
                List.of(new Evidence(
                    EvidenceKind.DOCUMENTED_FIELD,
                    "stm8a-family",
                    "Part belongs to STM8A automotive family: " + part.subfamily()))
            );
        }
        return new SupportDecision(
            false,
            Optional.empty(),
            "Part " + part.exactPart() + " is not an STM8A device (family: " + part.family() + ")",
            List.of()
        );
    }
}
