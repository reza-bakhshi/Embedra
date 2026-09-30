package io.github.rezabakhshi.embedra.core.stm32.input;

import java.util.OptionalLong;

/** Address facts encoded in an STM32 input, without a selected device or inferred base. */
public sealed interface Stm32AddressedInput permits Stm32ElfInput, Stm32IntelHexInput {
    Format format();

    OptionalLong encodedEntryPoint();

    enum Format {
        ELF,
        INTEL_HEX
    }
}
