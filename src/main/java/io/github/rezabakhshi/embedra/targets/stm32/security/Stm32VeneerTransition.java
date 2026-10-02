package io.github.rezabakhshi.embedra.targets.stm32.security;

import io.github.rezabakhshi.embedra.core.io.AddressRange;
import java.util.Objects;

/**
 * One evidence-backed secure/non-secure callable transition.
 *
 * <p>A transition names the non-secure-callable address range, the secure
 * target region it must resolve to, and the evidence id that establishes it.
 * Instruction semantics are deliberately absent: they are never fabricated and
 * require the actual instruction bytes.</p>
 */
public record Stm32VeneerTransition(String id, AddressRange nscRange,
        String secureTargetRegionId, String evidenceId) {
    public Stm32VeneerTransition {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(nscRange, "nscRange");
        Objects.requireNonNull(secureTargetRegionId, "secureTargetRegionId");
        Objects.requireNonNull(evidenceId, "evidenceId");
        if (id.isBlank() || secureTargetRegionId.isBlank() || evidenceId.isBlank()) {
            throw new IllegalArgumentException("Veneer transition identity is incomplete");
        }
        if (!Stm32SecurityWindow.ADDRESS_SPACE.equals(nscRange.addressSpace())
                || nscRange.length() <= 0) {
            throw new IllegalArgumentException(
                "Veneer transition requires a positive MCU non-secure-callable range");
        }
    }
}
