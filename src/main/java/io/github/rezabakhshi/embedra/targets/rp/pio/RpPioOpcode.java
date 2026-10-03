package io.github.rezabakhshi.embedra.targets.rp.pio;

/**
 * Standard instruction opcodes for Raspberry Pi PIO state machines.
 */
public enum RpPioOpcode {
    JMP(0, "jmp"),
    WAIT(1, "wait"),
    IN(2, "in"),
    OUT(3, "out"),
    PUSH(4, "push"),
    PULL(4, "pull"),
    MOV(5, "mov"),
    IRQ(6, "irq"),
    SET(7, "set");

    private final int encoding;

    private final String mnemonic;

    RpPioOpcode(int encoding, String mnemonic) {
        this.encoding = encoding;
        this.mnemonic = mnemonic;
    }

    public int encoding() {
        return encoding;
    }

    public String mnemonic() {
        return mnemonic;
    }
}
