package io.github.rezabakhshi.embedra.analyzers.rp;

import io.github.rezabakhshi.embedra.formats.rp.uf2.RpUf2Segment;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Pure input context providing image segments, symbols, and strings for RP component analysis.
 */
public final class RpAnalysisContext {

    private final List<RpUf2Segment> segments;

    private final List<String> symbols;

    private final List<String> strings;

    public RpAnalysisContext(List<RpUf2Segment> segments, List<String> symbols, List<String> strings) {
        this.segments = List.copyOf(Objects.requireNonNull(segments, "segments must not be null"));
        this.symbols = List.copyOf(Objects.requireNonNull(symbols, "symbols must not be null"));
        this.strings = List.copyOf(Objects.requireNonNull(strings, "strings must not be null"));
    }

    public static RpAnalysisContext fromBytes(byte[] data, long baseAddress) {
        Objects.requireNonNull(data, "data must not be null");
        List<RpUf2Segment> segments = List.of(new RpUf2Segment(baseAddress, data, Optional.empty()));
        List<String> extractedStrings = extractStrings(data, 4);
        return new RpAnalysisContext(segments, List.of(), extractedStrings);
    }

    public static RpAnalysisContext fromSegments(List<RpUf2Segment> segments, List<String> symbols) {
        Objects.requireNonNull(segments, "segments must not be null");
        List<String> extractedStrings = new ArrayList<>();
        for (RpUf2Segment seg : segments) {
            extractedStrings.addAll(extractStrings(seg.data(), 4));
        }
        return new RpAnalysisContext(segments, symbols != null ? symbols : List.of(), extractedStrings);
    }

    public List<RpUf2Segment> segments() {
        return segments;
    }

    public List<String> symbols() {
        return symbols;
    }

    public List<String> strings() {
        return strings;
    }

    public static List<String> extractStrings(byte[] data, int minLength) {
        List<String> result = new ArrayList<>();
        int start = -1;
        for (int i = 0; i < data.length; i++) {
            byte b = data[i];
            if (b >= 32 && b <= 126) {
                if (start < 0) {
                    start = i;
                }
            } else if (b == 0) {
                if (start >= 0 && (i - start) >= minLength) {
                    result.add(new String(data, start, i - start, StandardCharsets.UTF_8));
                }
                start = -1;
            } else {
                start = -1;
            }
        }
        return result;
    }
}
