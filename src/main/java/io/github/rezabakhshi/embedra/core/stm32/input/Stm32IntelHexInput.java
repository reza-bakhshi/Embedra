package io.github.rezabakhshi.embedra.core.stm32.input;

import java.util.List;
import java.util.Objects;
import java.util.OptionalLong;

/** Intel HEX data record addresses, including extended address records. */
public record Stm32IntelHexInput(OptionalLong encodedEntryPoint,
        List<DataRecord> dataRecords) implements Stm32AddressedInput {
    private static final long ADDRESS_SPACE_END = 0x1_0000_0000L;

    public Stm32IntelHexInput {
        Objects.requireNonNull(encodedEntryPoint, "encodedEntryPoint");
        if (encodedEntryPoint.isPresent()) {
            checkAddress(encodedEntryPoint.getAsLong(), 0);
        }
        dataRecords = List.copyOf(Objects.requireNonNull(dataRecords, "dataRecords"));
    }

    @Override
    public Format format() {
        return Format.INTEL_HEX;
    }

    public record DataRecord(long encodedAddress, int length, long sourceOffset, int line) {
        public DataRecord {
            checkAddress(encodedAddress, length);
            if (sourceOffset < 0 || line <= 0) {
                throw new IllegalArgumentException("Invalid Intel HEX source position");
            }
        }
    }

    private static void checkAddress(long address, long length) {
        if (address < 0 || length < 0 || address >= ADDRESS_SPACE_END
            || length > ADDRESS_SPACE_END - address) {
            throw new IllegalArgumentException("Intel HEX address exceeds the 32-bit target space");
        }
    }
}
