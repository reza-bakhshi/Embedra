package io.github.rezabakhshi.embedra.targets.nordic.peripheral;

import java.util.Objects;

/**
 * Pure transform from Nordic peripheral definitions into Ghidra registers, comments, and types.
 */
public final class NordicPeripheralSchemaTransform {

    private NordicPeripheralSchemaTransform() {
    }

    public static String formatRegisterComment(NordicRegister register) {
        Objects.requireNonNull(register, "register must not be null");
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("[%s] (0x%08X, 32-bit)", register.name(), register.address()));
        if (register.isEasyDma()) {
            String dmaStr = register.easyDmaType() != null ? register.easyDmaType().name() : "CHANNEL";
            sb.append(" [EasyDMA: ").append(dmaStr).append("]");
        }
        if (!register.description().isBlank()) {
            sb.append(" ").append(register.description());
        }
        if (!register.bitfields().isEmpty()) {
            sb.append("\nBitfields:");
            for (NordicBitField bf : register.bitfields()) {
                String range = (bf.bitWidth() == 1)
                    ? String.valueOf(bf.bitOffset())
                    : String.format("%d:%d", bf.bitOffset() + bf.bitWidth() - 1, bf.bitOffset());
                sb.append(String.format("\n  [%s] %s (%s, 0x%08X)",
                    range, bf.name(), bf.access(), bf.mask()));
                if (!bf.description().isBlank()) {
                    sb.append(" - ").append(bf.description());
                }
            }
        }
        return sb.toString();
    }

    public static String formatPeripheralPlateComment(NordicPeripheral peripheral) {
        Objects.requireNonNull(peripheral, "peripheral must not be null");
        return String.format(
            "=== Nordic nRF %s Peripheral Block ===\nBase: 0x%08X - 0x%08X\nRegisters: %d\nDescription: %s",
            peripheral.name(),
            peripheral.baseAddress(),
            peripheral.endExclusive() - 1L,
            peripheral.registers().size(),
            peripheral.description().isBlank() ? "Hardware peripheral block" : peripheral.description()
        );
    }
}
