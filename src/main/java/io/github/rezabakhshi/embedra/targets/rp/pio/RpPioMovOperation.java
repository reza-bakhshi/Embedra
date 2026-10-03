package io.github.rezabakhshi.embedra.targets.rp.pio;

/**
 * Unary transform operation applied during PIO MOV instruction (bits 4:3).
 */
public enum RpPioMovOperation {
    NONE(0, ""),
    INVERT(1, "!"),
    BIT_REVERSE(2, "::"),
    RESERVED(3, "reserved_op");

    private final int code;

    private final String prefix;

    RpPioMovOperation(int code, String prefix) {
        this.code = code;
        this.prefix = prefix;
    }

    public int code() {
        return code;
    }

    public String prefix() {
        return prefix;
    }

    public static RpPioMovOperation fromCode(int code) {
        for (RpPioMovOperation op : values()) {
            if (op.code == (code & 0x3)) {
                return op;
            }
        }
        return NONE;
    }
}
