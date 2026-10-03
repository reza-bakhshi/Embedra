package io.github.rezabakhshi.embedra.targets.rp.pio;

/**
 * Destination register for PIO MOV instructions (bits 7:5).
 */
public enum RpPioMovDestination {
    PINS(0, "pins"),
    X(1, "x"),
    Y(2, "y"),
    RESERVED_3(3, "reserved_3"),
    EXEC(4, "exec"),
    PC(5, "pc"),
    ISR(6, "isr"),
    OSR(7, "osr");

    private final int code;

    private final String syntax;

    RpPioMovDestination(int code, String syntax) {
        this.code = code;
        this.syntax = syntax;
    }

    public int code() {
        return code;
    }

    public String syntax() {
        return syntax;
    }

    public static RpPioMovDestination fromCode(int code) {
        for (RpPioMovDestination dest : values()) {
            if (dest.code == (code & 0x7)) {
                return dest;
            }
        }
        return PINS;
    }
}
