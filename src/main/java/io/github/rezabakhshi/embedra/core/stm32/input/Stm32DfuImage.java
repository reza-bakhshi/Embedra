package io.github.rezabakhshi.embedra.core.stm32.input;

import io.github.rezabakhshi.embedra.core.io.SourceRange;
import java.util.List;
import java.util.Objects;

/** Validated DfuSe v1 container metadata; element bytes remain in the source input. */
public record Stm32DfuImage(List<Target> targets, Suffix suffix) {
    public Stm32DfuImage {
        targets = List.copyOf(Objects.requireNonNull(targets, "targets"));
        Objects.requireNonNull(suffix, "suffix");
    }

    public record Target(int alternateSetting, String name, SourceRange bodyRange,
            List<Element> elements) {
        public Target {
            Objects.requireNonNull(name, "name");
            Objects.requireNonNull(bodyRange, "bodyRange");
            elements = List.copyOf(Objects.requireNonNull(elements, "elements"));
        }
    }

    public record Element(long encodedAddress, SourceRange dataRange) {
        public Element {
            Objects.requireNonNull(dataRange, "dataRange");
        }

        public long endExclusive() {
            return encodedAddress + dataRange.length();
        }
    }

    public record Suffix(int deviceVersion, int productId, int vendorId,
            int dfuVersion, long storedCrc) {
    }
}
