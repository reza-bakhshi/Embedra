package io.github.rezabakhshi.embedra.targets.stm32.mp;

import io.github.rezabakhshi.embedra.targets.SupportDecision;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Registry of verified STM32MP heterogeneous target providers.
 *
 * <p>Isolates MPU heterogeneous device planning from ordinary MCU workflows (STM-015).</p>
 */
public final class Stm32MpProviderRegistry {
    private static final Stm32MpProviderRegistry INSTANCE = new Stm32MpProviderRegistry(
        List.of(
            new Stm32Mp157TargetProvider(),
            new Stm32Mp257TargetProvider(),
            new Stm32Mp135TargetProvider()
        )
    );

    private final List<Stm32MpTargetProvider> providers;

    public Stm32MpProviderRegistry(List<Stm32MpTargetProvider> providers) {
        this.providers = List.copyOf(providers);
    }

    public static Stm32MpProviderRegistry instance() {
        return INSTANCE;
    }

    public List<Stm32MpTargetProvider> providers() {
        return providers;
    }

    public Optional<Stm32MpTargetProvider> findByExactPart(String exactPart) {
        Objects.requireNonNull(exactPart, "exactPart");
        if (exactPart.isBlank()) {
            throw new IllegalArgumentException("Exact part query must not be blank");
        }
        return providers.stream()
            .filter(provider -> provider.matches(exactPart))
            .findFirst();
    }

    public Stm32MpTargetProvider getRequired(String exactPart) {
        return findByExactPart(exactPart)
            .orElseThrow(() -> new IllegalArgumentException("Unknown or uncurated STM32MP target: " + exactPart));
    }

    public boolean containsExactPart(String exactPart) {
        if (exactPart == null || exactPart.isBlank()) {
            return false;
        }
        return providers.stream().anyMatch(provider -> provider.matches(exactPart));
    }

    public SupportDecision supports(String exactPartOrLine) {
        if (exactPartOrLine == null || exactPartOrLine.isBlank()) {
            return new SupportDecision(false, Optional.empty(), "Query was blank", List.of());
        }
        return findByExactPart(exactPartOrLine)
            .map(provider -> provider.supports(exactPartOrLine))
            .orElseGet(() -> new SupportDecision(
                false,
                Optional.empty(),
                "No STM32MP provider matched: " + exactPartOrLine,
                List.of()
            ));
    }
}
