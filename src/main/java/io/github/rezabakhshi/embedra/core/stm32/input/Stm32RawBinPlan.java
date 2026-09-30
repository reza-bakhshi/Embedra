package io.github.rezabakhshi.embedra.core.stm32.input;

import io.github.rezabakhshi.embedra.core.ParserLimits;
import java.util.Objects;

/** Explicit exact-part and base selection for bytes that encode no address. */
public final class Stm32RawBinPlan {
    private static final long ADDRESS_SPACE_END = 0x1_0000_0000L;

    private final String exactPart;

    private final long baseAddress;

    private final long length;

    private Stm32RawBinPlan(String exactPart, long baseAddress, long length) {
        this.exactPart = exactPart;
        this.baseAddress = baseAddress;
        this.length = length;
    }

    public static Stm32RawBinPlan explicit(String exactPart, long baseAddress, long length,
            Stm32PartSelection selection, ParserLimits limits) {
        Objects.requireNonNull(exactPart, "exactPart");
        Objects.requireNonNull(selection, "selection");
        Objects.requireNonNull(limits, "limits");
        if (!selection.containsExactPart(exactPart)) {
            throw new IllegalArgumentException("Select an exact curated STM32 part");
        }
        if (length <= 0 || length > limits.maxInputBytes()
                || length > limits.maxExtractedBytes()) {
            throw new IllegalArgumentException("Raw BIN length is outside parser limits");
        }
        if (baseAddress < 0 || baseAddress >= ADDRESS_SPACE_END
                || length > ADDRESS_SPACE_END - baseAddress) {
            throw new IllegalArgumentException("Explicit raw BIN base exceeds 32-bit space");
        }
        return new Stm32RawBinPlan(exactPart, baseAddress, length);
    }

    public String exactPart() {
        return exactPart;
    }

    public long baseAddress() {
        return baseAddress;
    }

    public long length() {
        return length;
    }
}
