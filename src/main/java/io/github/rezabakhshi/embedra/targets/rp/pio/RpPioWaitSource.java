package io.github.rezabakhshi.embedra.targets.rp.pio;

/**
 * Event source for PIO WAIT instructions (bits 6:5).
 */
public enum RpPioWaitSource {
    GPIO(0, "gpio"),
    PIN(1, "pin"),
    IRQ(2, "irq"),
    RESERVED(3, "reserved");

    private final int code;

    private final String syntax;

    RpPioWaitSource(int code, String syntax) {
        this.code = code;
        this.syntax = syntax;
    }

    public int code() {
        return code;
    }

    public String syntax() {
        return syntax;
    }

    public static RpPioWaitSource fromCode(int code) {
        for (RpPioWaitSource src : values()) {
            if (src.code == (code & 0x3)) {
                return src;
            }
        }
        return RESERVED;
    }
}
