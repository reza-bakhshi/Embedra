package io.github.rezabakhshi.embedra.analyzers.crypto.hardware;

import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.OptionalLong;

/**
 * Observed memory or MMIO access event parsed from instruction disassembly or P-code (AN-013).
 *
 * @param instructionAddress address of the instruction executing the access
 * @param targetAddress target memory or peripheral register address
 * @param write true for write/store, false for read/load
 * @param value written constant value if statically resolved
 */
public record HardwareMemoryAccess(
        long instructionAddress,
        long targetAddress,
        boolean write,
        OptionalLong value) {

    public HardwareMemoryAccess {
        if (instructionAddress < 0) {
            throw new IllegalArgumentException("instructionAddress must be non-negative: " + instructionAddress);
        }
        if (targetAddress < 0) {
            throw new IllegalArgumentException("targetAddress must be non-negative: " + targetAddress);
        }
        Objects.requireNonNull(value, "value must not be null");
    }

    public static HardwareMemoryAccess write(long instructionAddress, long targetAddress, long val) {
        return new HardwareMemoryAccess(instructionAddress, targetAddress, true, OptionalLong.of(val));
    }

    public static HardwareMemoryAccess write(long instructionAddress, long targetAddress) {
        return new HardwareMemoryAccess(instructionAddress, targetAddress, true, OptionalLong.empty());
    }

    public static HardwareMemoryAccess read(long instructionAddress, long targetAddress) {
        return new HardwareMemoryAccess(instructionAddress, targetAddress, false, OptionalLong.empty());
    }
}
