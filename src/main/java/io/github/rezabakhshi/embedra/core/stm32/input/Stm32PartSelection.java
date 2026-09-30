package io.github.rezabakhshi.embedra.core.stm32.input;

/** Exact-part membership supplied by a verified device selection source. */
@FunctionalInterface
public interface Stm32PartSelection {
    boolean containsExactPart(String exactPart);
}
