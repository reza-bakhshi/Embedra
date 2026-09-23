package io.github.rezabakhshi.embedra.formats.esp;

import io.github.rezabakhshi.embedra.core.io.SourceRange;
import java.util.Objects;
import java.util.Optional;

/** One validated executable image with distinct physical-flash provenance. */
public record EspExtractedExecutable(
        String name,
        EspExecutableRole role,
        Optional<String> partitionLabel,
        EspFlashRange flashRange,
        SourceRange sourceRange,
        EspImage image,
        byte[] bytes) {
    public EspExtractedExecutable {
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(role, "role");
        Objects.requireNonNull(partitionLabel, "partitionLabel");
        Objects.requireNonNull(flashRange, "flashRange");
        Objects.requireNonNull(sourceRange, "sourceRange");
        Objects.requireNonNull(image, "image");
        bytes = Objects.requireNonNull(bytes, "bytes").clone();
        if (name.isBlank() || flashRange.length() == 0
            || flashRange.offset() != sourceRange.offset()
            || flashRange.length() != sourceRange.length()
            || flashRange.length() != bytes.length
            || image.sourceRange().length() != bytes.length) {
            throw new IllegalArgumentException("Invalid extracted ESP executable");
        }
    }

    @Override
    public byte[] bytes() {
        return bytes.clone();
    }
}
