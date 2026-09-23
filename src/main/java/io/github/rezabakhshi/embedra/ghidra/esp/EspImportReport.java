package io.github.rezabakhshi.embedra.ghidra.esp;

import java.util.List;
import java.util.Objects;
import java.util.OptionalLong;

/** Immutable result produced only after an ESP mapping transaction commits. */
public record EspImportReport(
        boolean committed,
        String deviceId,
        String languageId,
        String compilerSpecId,
        List<EspMappedSegmentReport> segments,
        OptionalLong entryPoint) {
    public EspImportReport {
        Objects.requireNonNull(deviceId, "deviceId");
        Objects.requireNonNull(languageId, "languageId");
        Objects.requireNonNull(compilerSpecId, "compilerSpecId");
        segments = List.copyOf(segments);
        Objects.requireNonNull(entryPoint, "entryPoint");
        if (!committed || deviceId.isBlank() || languageId.isBlank()
            || compilerSpecId.isBlank() || segments.isEmpty()) {
            throw new IllegalArgumentException("Import report requires a committed mapping");
        }
    }
}
