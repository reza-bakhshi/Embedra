package io.github.rezabakhshi.embedra.targets.rp.pio;

/**
 * Branch conditions for PIO JMP instructions (bits 7:5).
 */
public enum RpPioCondition {
    ALWAYS(0, ""),
    NOT_X(1, "!x"),
    X_POST_DEC(2, "x--"),
    NOT_Y(3, "!y"),
    Y_POST_DEC(4, "y--"),
    X_NOT_EQUAL_Y(5, "x!=y"),
    PIN(6, "pin"),
    NOT_OSRE(7, "!osre");

    private final int code;

    private final String syntax;

    RpPioCondition(int code, String syntax) {
        this.code = code;
        this.syntax = syntax;
    }

    public int code() {
        return code;
    }

    public String syntax() {
        return syntax;
    }

    public static RpPioCondition fromCode(int code) {
        for (RpPioCondition cond : values()) {
            if (cond.code == (code & 0x7)) {
                return cond;
            }
        }
        return ALWAYS;
    }
}
