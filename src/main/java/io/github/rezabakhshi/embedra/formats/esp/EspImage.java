package io.github.rezabakhshi.embedra.formats.esp;

import io.github.rezabakhshi.embedra.core.io.SourceRange;
import java.util.List;
import java.util.Objects;

/** Complete immutable structural model of one ESP application image. */
public record EspImage(
        EspImageHeader header,
        List<EspImageSegment> segments,
        EspImageFooter footer,
        SourceRange sourceRange) {
    public EspImage {
        Objects.requireNonNull(header, "header");
        segments = List.copyOf(segments);
        Objects.requireNonNull(footer, "footer");
        Objects.requireNonNull(sourceRange, "sourceRange");
        if (segments.size() != header.segmentCount()) {
            throw new IllegalArgumentException("Header and parsed segment counts differ");
        }
    }
}
