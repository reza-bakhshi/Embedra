package io.github.rezabakhshi.embedra.targets.esp;

import io.github.rezabakhshi.embedra.core.io.AddressRange;
import io.github.rezabakhshi.embedra.core.model.Evidence;
import io.github.rezabakhshi.embedra.formats.esp.EspImage;
import io.github.rezabakhshi.embedra.formats.esp.EspImageSegment;
import io.github.rezabakhshi.embedra.targets.EntryPointDecision;
import io.github.rezabakhshi.embedra.targets.LanguageSelection;
import io.github.rezabakhshi.embedra.targets.MemoryClassification;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Function;

/** Shared structural entry validation parameterized by language and provider memory data. */
public final class EspEntryPointValidator {
    private EspEntryPointValidator() {
    }

    public static EntryPointDecision validate(long address, EspImage image,
            LanguageSelection language, String addressSpace,
            Function<AddressRange, MemoryClassification> classifier) {
        Objects.requireNonNull(image, "image");
        Objects.requireNonNull(language, "language");
        Objects.requireNonNull(addressSpace, "addressSpace");
        Objects.requireNonNull(classifier, "classifier");
        if (addressSpace.isBlank()) {
            throw new IllegalArgumentException("Entry address space must not be blank");
        }
        if (address < 0 || address > 0xffff_ffffL) {
            throw new IllegalArgumentException("Entry address must be an unsigned 32-bit value");
        }
        if (address % language.instructionAlignmentBytes() != 0) {
            return rejected(address, "Entry address violates language alignment",
                Optional.empty(), language.evidence());
        }
        MemoryClassification addressClass = classifier.apply(
            new AddressRange(addressSpace, address, 1));
        if (!addressClass.mappable()) {
            return rejected(address, "Entry address is outside recognized memory",
                Optional.of(addressClass), addressClass.evidence());
        }
        if (!addressClass.executable()) {
            return rejected(address, "Entry address is not in executable memory",
                Optional.of(addressClass), addressClass.evidence());
        }
        Optional<EspImageSegment> containingSegment = image.segments().stream()
            .filter(segment -> contains(segment.targetRange(), address)).findFirst();
        if (containingSegment.isEmpty()) {
            return rejected(address, "Entry address is not inside a mapped segment",
                Optional.of(addressClass), addressClass.evidence());
        }
        MemoryClassification segmentClass = classifier.apply(
            containingSegment.orElseThrow().targetRange());
        if (!segmentClass.executable()) {
            return rejected(address, "Mapped segment is not executable",
                Optional.of(segmentClass), segmentClass.evidence());
        }
        ArrayList<Evidence> evidence = new ArrayList<>(language.evidence());
        evidence.addAll(segmentClass.evidence());
        return new EntryPointDecision(true, address,
            "Entry address satisfies language alignment and is inside a mapped executable segment",
            Optional.of(segmentClass), List.copyOf(evidence));
    }

    private static EntryPointDecision rejected(long address, String reason,
            Optional<MemoryClassification> classification, List<Evidence> evidence) {
        return new EntryPointDecision(false, address, reason, classification, evidence);
    }

    private static boolean contains(AddressRange range, long address) {
        return address >= range.start() && address < range.endExclusive();
    }
}
