package io.github.rezabakhshi.embedra.targets.rp;

/**
 * Models RP2040 bus-level atomic register access aliases.
 * <p>
 * Peripheral registers mapped in {@code 0x40000000..0x4005FFFF} have atomic aliases
 * at {@code 0x50000000..0x5005FFFF} allowing single-cycle atomic bit manipulations:
 * <ul>
 *   <li>{@code +0x0000}: Normal read/write</li>
 *   <li>{@code +0x1000}: Atomic bitmask XOR</li>
 *   <li>{@code +0x2000}: Atomic bitmask SET</li>
 *   <li>{@code +0x3000}: Atomic bitmask CLEAR</li>
 * </ul>
 */
public final class Rp2040AtomicAlias {

    public static final long PERIPHERALS_BASE = 0x40000000L;

    public static final long PERIPHERALS_END = 0x40060000L;

    public static final long ATOMIC_ALIAS_BASE = 0x50000000L;

    public static final long ATOMIC_ALIAS_END = 0x50060000L;


    public enum Operation {
        NORMAL,
        XOR,
        SET,
        CLEAR
    }

    private Rp2040AtomicAlias() {
    }

    public static boolean isAtomicAlias(long address) {
        return address >= ATOMIC_ALIAS_BASE && address < ATOMIC_ALIAS_END;
    }

    public static boolean isPeripheral(long address) {
        return address >= PERIPHERALS_BASE && address < PERIPHERALS_END;
    }

    public static long toAtomicAlias(long peripheralAddress, Operation op) {
        if (!isPeripheral(peripheralAddress)) {
            throw new IllegalArgumentException(
                    "Address 0x" + Long.toHexString(peripheralAddress) + " is not an RP2040 peripheral address");
        }
        long offset = peripheralAddress - PERIPHERALS_BASE;
        long opOffset = switch (op) {
            case NORMAL -> 0x0000L;
            case XOR -> 0x1000L;
            case SET -> 0x2000L;
            case CLEAR -> 0x3000L;
        };
        return ATOMIC_ALIAS_BASE + offset + opOffset;
    }

    public static long toNormalAddress(long aliasAddress) {
        if (!isAtomicAlias(aliasAddress)) {
            return aliasAddress;
        }
        long offset = aliasAddress - ATOMIC_ALIAS_BASE;
        long blockOffset = offset % 0x4000L;
        long peripheralBlock = offset - blockOffset;
        long regOffset = blockOffset % 0x1000L;
        return PERIPHERALS_BASE + peripheralBlock + regOffset;
    }

    public static Operation resolveOperation(long aliasAddress) {
        if (!isAtomicAlias(aliasAddress)) {
            return Operation.NORMAL;
        }
        long offset = (aliasAddress - ATOMIC_ALIAS_BASE) % 0x4000L;
        long subBlock = offset / 0x1000L;
        return switch ((int) subBlock) {
            case 1 -> Operation.XOR;
            case 2 -> Operation.SET;
            case 3 -> Operation.CLEAR;
            default -> Operation.NORMAL;
        };
    }
}
