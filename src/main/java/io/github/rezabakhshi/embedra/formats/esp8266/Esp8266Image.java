package io.github.rezabakhshi.embedra.formats.esp8266;

import io.github.rezabakhshi.embedra.core.io.SourceRange;
import java.util.List;
import java.util.Objects;
import java.util.OptionalLong;

/** Complete immutable model of one ESP8266 legacy executable image. */
public record Esp8266Image(
        Esp8266ImageHeader header,
        List<Esp8266ImageSegment> segments,
        int storedChecksum,
        int calculatedChecksum,
        OptionalLong storedSdkCrc32,
        OptionalLong calculatedSdkCrc32,
        SourceRange sourceRange) {
    public Esp8266Image {
        Objects.requireNonNull(header, "header");
        segments = List.copyOf(segments);
        Objects.requireNonNull(storedSdkCrc32, "storedSdkCrc32");
        Objects.requireNonNull(calculatedSdkCrc32, "calculatedSdkCrc32");
        Objects.requireNonNull(sourceRange, "sourceRange");
        if (segments.size() != header.segmentCount()) {
            throw new IllegalArgumentException("Header and parsed segment counts differ");
        }
        if (storedSdkCrc32.isPresent() != calculatedSdkCrc32.isPresent()) {
            throw new IllegalArgumentException("Stored and calculated SDK CRC states differ");
        }
        if ((header.version() == Esp8266ImageVersion.VERSION_2)
            != storedSdkCrc32.isPresent()) {
            throw new IllegalArgumentException("SDK CRC presence does not match image version");
        }
    }
}
