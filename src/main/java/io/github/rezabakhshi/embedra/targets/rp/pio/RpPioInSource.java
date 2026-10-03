package io.github.rezabakhshi.embedra.targets.rp.pio;

/**
 * Data source for PIO IN instructions (bits 7:5).
 */
public enum RpPioInSource {
    PINS(0, "pins"),
    X(1, "x"),
    Y(2, "y"),
    NULL(3, "null"),
    RESERVED_4(4, "reserved_4"),
    STATUS(5, "status"),
    ISR(6, "isr"),
    OSR(7, "osr");

    private final int code;

    private final String syntax;

    RpPioInSource(int code, String syntax) {
        this.code = code;
        this.syntax = syntax;
    }

    public int code() {
        return code;
    }

    public String syntax() {
        return syntax;
    }

    public static RpPioInSource fromCode(int code) {
        for (RpPioInSource src : values()) {
            if (src.code == (code & 0x7)) {
                return src;
            }
        }
        return NULL;
    }
}
