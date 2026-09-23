package io.github.rezabakhshi.embedra.formats.esp;

import io.github.rezabakhshi.embedra.core.io.SourceRange;
import java.util.Objects;

/** One of the two redundant 32-byte OTA selection records. */
public record EspOtaSelectRecord(
        int copyIndex,
        long sequence,
        long rawState,
        EspOtaImageState state,
        long storedCrc,
        long calculatedCrc,
        EspOtaRecordValidity validity,
        SourceRange sourceRange) {
    public EspOtaSelectRecord {
        Objects.requireNonNull(state, "state");
        Objects.requireNonNull(validity, "validity");
        Objects.requireNonNull(sourceRange, "sourceRange");
        if (copyIndex < 0 || copyIndex > 1 || sequence < 0
            || sequence > 0xffff_ffffL || rawState < 0
            || rawState > 0xffff_ffffL || storedCrc < 0
            || storedCrc > 0xffff_ffffL || calculatedCrc < 0
            || calculatedCrc > 0xffff_ffffL || sourceRange.length() != 32) {
            throw new IllegalArgumentException("Invalid OTA select record");
        }
    }
}
