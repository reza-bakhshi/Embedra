package io.github.rezabakhshi.embedra.targets.atmel.peripheral;

import java.util.List;
import java.util.Objects;

/**
 * Pure transform from Atmel/Microchip peripheral definitions into Ghidra registers, comments, and schemas.
 */
public final class AtmelPeripheralSchemaTransform {

    private AtmelPeripheralSchemaTransform() {
    }

    public static String formatRegisterComment(AtmelRegister register) {
        Objects.requireNonNull(register, "register must not be null");
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("[%s] (0x%X, %d-bit)", register.name(), register.address(), register.widthBits()));
        if (!register.description().isBlank()) {
            sb.append(" ").append(register.description());
        }
        if (!register.bitfields().isEmpty()) {
            sb.append("\nBitfields:");
            for (AtmelBitField bf : register.bitfields()) {
                String range = (bf.bitWidth() == 1)
                    ? String.valueOf(bf.bitOffset())
                    : String.format("%d:%d", bf.bitOffset() + bf.bitWidth() - 1, bf.bitOffset());
                sb.append(String.format("\n  [%s] %s (%s, 0x%X)",
                    range, bf.name(), bf.access(), bf.mask()));
                if (!bf.description().isBlank()) {
                    sb.append(" - ").append(bf.description());
                }
            }
        }
        return sb.toString();
    }

    public static String formatPeripheralPlateComment(AtmelPeripheral peripheral) {
        Objects.requireNonNull(peripheral, "peripheral must not be null");
        return String.format(
            "=== Atmel %s Peripheral Block ===\nSpace: %s\nBase: 0x%X - 0x%X\nRegisters: %d\nDescription: %s",
            peripheral.name(),
            peripheral.addressSpace(),
            peripheral.baseAddress(),
            peripheral.effectiveEndAddress() - 1L,
            peripheral.registers().size(),
            peripheral.description().isBlank() ? "Hardware peripheral block" : peripheral.description()
        );
    }

    public static String formatIoPortComment(AtmelIoPort ioPort) {
        Objects.requireNonNull(ioPort, "ioPort must not be null");
        return String.format(
            "=== I/O Port %s (%d-pin) ===\nData: %s\nDirection: %s\nInput: %s",
            ioPort.name(),
            ioPort.pinCount(),
            ioPort.dataRegister(),
            ioPort.directionRegister(),
            ioPort.inputRegister()
        );
    }

    public static String formatFuseByteComment(AtmelFuseByte fuseByte, long value) {
        Objects.requireNonNull(fuseByte, "fuseByte must not be null");
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("=== Fuse %s (0x%02X) ===\nValue: 0x%02X (Default: 0x%02X)",
            fuseByte.name(), fuseByte.address(), value, fuseByte.defaultValue()));
        if (!fuseByte.description().isBlank()) {
            sb.append("\nDescription: ").append(fuseByte.description());
        }
        if (!fuseByte.bits().isEmpty()) {
            sb.append("\nFuses:");
            for (AtmelFuseBit bit : fuseByte.bits()) {
                long extracted = (value >> bit.bitOffset()) & ((1L << bit.bitWidth()) - 1L);
                boolean isProgrammed = bit.isProgrammed(value);
                String state = isProgrammed ? "PROGRAMMED" : "UNPROGRAMMED";
                String range = (bit.bitWidth() == 1)
                    ? String.valueOf(bit.bitOffset())
                    : String.format("%d:%d", bit.bitOffset() + bit.bitWidth() - 1, bit.bitOffset());
                sb.append(String.format("\n  [%s] %s = 0x%X [%s] (%s)",
                    range, bit.name(), extracted, state, bit.polarity()));
                if (!bit.description().isBlank()) {
                    sb.append(" - ").append(bit.description());
                }
            }
        }
        return sb.toString();
    }

    public static String formatInterruptPlateComment(List<AtmelInterrupt> interrupts) {
        Objects.requireNonNull(interrupts, "interrupts must not be null");
        StringBuilder sb = new StringBuilder();
        sb.append("=== Interrupt Vector Table ===\nVectors: ").append(interrupts.size());
        for (AtmelInterrupt intr : interrupts) {
            sb.append(String.format("\n  [%2d] %s", intr.index(), intr.name()));
            if (!intr.description().isBlank()) {
                sb.append(" - ").append(intr.description());
            }
        }
        return sb.toString();
    }
}
