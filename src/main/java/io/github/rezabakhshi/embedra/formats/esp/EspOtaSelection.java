package io.github.rezabakhshi.embedra.formats.esp;

import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalInt;

/** Validated OTA records and a selection only when the referenced slot is populated. */
public record EspOtaSelection(
        List<EspOtaSelectRecord> records,
        OptionalInt activeSlot,
        Optional<String> activePartitionLabel) {
    public EspOtaSelection {
        records = List.copyOf(records);
        Objects.requireNonNull(activeSlot, "activeSlot");
        Objects.requireNonNull(activePartitionLabel, "activePartitionLabel");
        if (records.size() != 2
            || activeSlot.isPresent() != activePartitionLabel.isPresent()) {
            throw new IllegalArgumentException("Invalid OTA selection model");
        }
    }
}
