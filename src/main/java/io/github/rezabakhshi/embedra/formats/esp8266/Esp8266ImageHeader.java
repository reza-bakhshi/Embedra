package io.github.rezabakhshi.embedra.formats.esp8266;

import io.github.rezabakhshi.embedra.core.io.SourceRange;
import java.util.Objects;

/** Immutable normalized ESP8266 legacy image header. */
public record Esp8266ImageHeader(
        Esp8266ImageVersion version,
        int segmentCount,
        int flashMode,
        int flashSizeFrequency,
        long entryPoint,
        SourceRange sourceRange) {
    public Esp8266ImageHeader {
        Objects.requireNonNull(version, "version");
        Objects.requireNonNull(sourceRange, "sourceRange");
        if (segmentCount <= 0 || segmentCount > Esp8266ImageDetector.MAX_SEGMENTS) {
            throw new IllegalArgumentException("Invalid ESP8266 segment count");
        }
    }
}
