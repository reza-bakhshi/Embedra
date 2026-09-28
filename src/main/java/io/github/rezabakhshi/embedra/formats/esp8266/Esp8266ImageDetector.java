package io.github.rezabakhshi.embedra.formats.esp8266;

import java.util.Objects;

/** Conservative detector for ESP8266 version 1 and version 2 images. */
public final class Esp8266ImageDetector {
    static final int HEADER_LENGTH = 8;

    static final int MAX_SEGMENTS = 16;

    static final int VERSION_2_MARKER = 4;

    private Esp8266ImageDetector() {
    }

    public static Esp8266ImageDetection detect(byte[] input) {
        Objects.requireNonNull(input, "input");
        if (input.length == 0) {
            return Esp8266ImageDetection.NO_MATCH;
        }
        int magic = Byte.toUnsignedInt(input[0]);
        if (magic != Esp8266ImageVersion.VERSION_1.magic()
            && magic != Esp8266ImageVersion.VERSION_2.magic()) {
            return Esp8266ImageDetection.NO_MATCH;
        }
        if (input.length < HEADER_LENGTH) {
            return Esp8266ImageDetection.MALFORMED;
        }
        int countOrMarker = Byte.toUnsignedInt(input[1]);
        if (magic == Esp8266ImageVersion.VERSION_1.magic()
            && (countOrMarker == 0 || countOrMarker > MAX_SEGMENTS)) {
            return Esp8266ImageDetection.MALFORMED;
        }
        if (magic == Esp8266ImageVersion.VERSION_2.magic()
            && countOrMarker != VERSION_2_MARKER) {
            return Esp8266ImageDetection.MALFORMED;
        }
        return Esp8266ImageDetection.MATCH;
    }
}
