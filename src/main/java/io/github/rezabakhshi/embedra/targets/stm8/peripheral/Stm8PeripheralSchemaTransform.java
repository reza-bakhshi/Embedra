package io.github.rezabakhshi.embedra.targets.stm8.peripheral;

import java.util.Objects;

/**
 * Pure transform from STM8 peripheral definitions into Ghidra registers, comments, and types (STM8-008).
 */
public final class Stm8PeripheralSchemaTransform {

    private Stm8PeripheralSchemaTransform() {
    }

    public static String formatRegisterComment(Stm8Register register) {
        Objects.requireNonNull(register, "register must not be null");
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("[%s] (0x%04X, 8-bit)", register.name(), register.address()));
        if (!register.description().isBlank()) {
            sb.append(" ").append(register.description());
        }
        if (!register.bitfields().isEmpty()) {
            sb.append("\nBitfields:");
            for (Stm8BitField bf : register.bitfields()) {
                String range = (bf.bitWidth() == 1)
                    ? String.valueOf(bf.bitOffset())
                    : String.format("%d:%d", bf.bitOffset() + bf.bitWidth() - 1, bf.bitOffset());
                sb.append(String.format("\n  [%s] %s (%s, 0x%02X)",
                    range, bf.name(), bf.access(), bf.mask()));
                if (!bf.description().isBlank()) {
                    sb.append(" - ").append(bf.description());
                }
            }
        }
        return sb.toString();
    }

    public static String formatPeripheralPlateComment(Stm8Peripheral peripheral) {
        Objects.requireNonNull(peripheral, "peripheral must not be null");
        return String.format(
            "=== STM8 %s Peripheral Block ===\nBase: 0x%04X - 0x%04X\nRegisters: %d\nDescription: %s",
            peripheral.name(),
            peripheral.baseAddress(),
            peripheral.endExclusive() - 1,
            peripheral.registers().size(),
            peripheral.description().isBlank() ? "Hardware peripheral block" : peripheral.description()
        );
    }
}
