package io.github.rezabakhshi.embedra.targets.rp.pio;

import java.util.Objects;
import java.util.OptionalInt;

/**
 * Decoded representation of a 16-bit PIO instruction, including raw encoding, opcode, operands,
 * delay, and side-set attributes with uncertainty state.
 */
public record RpPioInstruction(
        int rawWord,
        RpPioOpcode opcode,
        String mnemonic,
        String operands,
        OptionalInt delay,
        OptionalInt sideSet,
        boolean isDelaySideUncertain,
        int rawDelaySide) {

    public RpPioInstruction {
        Objects.requireNonNull(opcode, "opcode must not be null");
        Objects.requireNonNull(mnemonic, "mnemonic must not be null");
        Objects.requireNonNull(operands, "operands must not be null");
        Objects.requireNonNull(delay, "delay must not be null");
        Objects.requireNonNull(sideSet, "sideSet must not be null");
    }

    /**
     * Formats the instruction in standard PIO assembly syntax with side-set, delay, or uncertainty annotations.
     */
    public String toAssemblyString() {
        StringBuilder sb = new StringBuilder(mnemonic);
        if (!operands.isBlank()) {
            sb.append(' ').append(operands);
        }
        if (sideSet.isPresent()) {
            sb.append(" side ").append(sideSet.getAsInt());
        }
        if (delay.isPresent() && delay.getAsInt() > 0) {
            sb.append(" [").append(delay.getAsInt()).append(']');
        }
        if (isDelaySideUncertain) {
            sb.append(" [delay/side: 0x").append(Integer.toHexString(rawDelaySide)).append(" (uncertain)]");
        }
        return sb.toString();
    }

    /**
     * Formats the instruction with raw hex word and opcode details.
     */
    public String toAnnotatedString() {
        return String.format("0x%04X: %-32s ; opcode=%s", rawWord, toAssemblyString(), opcode);
    }
}
