package io.github.rezabakhshi.embedra.targets.rp.pio;

/**
 * Destination register or pin group for PIO SET instructions (bits 7:5).
 */
public enum RpPioSetDestination {
    PINS(0, "pins"),
    X(1, "x"),
    Y(2, "y"),
    RESERVED_3(3, "reserved_3"),
    PINDIRS(4, "pindirs"),
    RESERVED_5(5, "reserved_5"),
    RESERVED_6(6, "reserved_6"),
    RESERVED_7(7, "reserved_7");

    private final int code;

    private final String syntax;

    RpPioSetDestination(int code, String syntax) {
        this.code = code;
        this.syntax = syntax;
    }

    public int code() {
        return code;
    }

    public String syntax() {
        return syntax;
    }

    public static RpPioSetDestination fromCode(int code) {
        for (RpPioSetDestination dest : values()) {
            if (dest.code == (code & 0x7)) {
                return dest;
            }
        }
        return PINS;
    }
}
