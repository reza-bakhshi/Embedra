package io.github.rezabakhshi.embedra.targets.rp.pio;

/**
 * Destination register or hardware target for PIO OUT instructions (bits 7:5).
 */
public enum RpPioOutDestination {
    PINS(0, "pins"),
    X(1, "x"),
    Y(2, "y"),
    NULL(3, "null"),
    PINDIRS(4, "pindirs"),
    PC(5, "pc"),
    ISR(6, "isr"),
    EXEC(7, "exec");

    private final int code;

    private final String syntax;

    RpPioOutDestination(int code, String syntax) {
        this.code = code;
        this.syntax = syntax;
    }

    public int code() {
        return code;
    }

    public String syntax() {
        return syntax;
    }

    public static RpPioOutDestination fromCode(int code) {
        for (RpPioOutDestination dest : values()) {
            if (dest.code == (code & 0x7)) {
                return dest;
            }
        }
        return NULL;
    }
}
