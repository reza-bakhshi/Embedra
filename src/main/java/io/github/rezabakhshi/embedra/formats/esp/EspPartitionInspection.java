package io.github.rezabakhshi.embedra.formats.esp;

import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.io.SourceRange;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

/** Immutable metadata-only output from one explicit partition handler. */
public record EspPartitionInspection(
        EspPartitionEntry entry,
        EspPartitionHandlerKind kind,
        EspPartitionDisposition disposition,
        SourceRange sourceRange,
        Map<String, String> metadata,
        List<Diagnostic> diagnostics,
        boolean sensitive) {
    public EspPartitionInspection {
        Objects.requireNonNull(entry, "entry");
        Objects.requireNonNull(kind, "kind");
        Objects.requireNonNull(disposition, "disposition");
        Objects.requireNonNull(sourceRange, "sourceRange");
        metadata = java.util.Collections.unmodifiableMap(new TreeMap<>(metadata));
        diagnostics = List.copyOf(diagnostics);
        if (entry.flashRange().offset() != sourceRange.offset()
            || entry.flashRange().length() != sourceRange.length()) {
            throw new IllegalArgumentException("Inspection range differs from partition");
        }
    }
}
