package io.github.rezabakhshi.embedra.formats.esp;

import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/** Optional ESP application metadata plus non-fatal extraction diagnostics. */
public record EspAppDescriptionResult(
        Optional<EspAppDescription> description,
        List<Diagnostic> diagnostics) {
    public EspAppDescriptionResult {
        Objects.requireNonNull(description, "description");
        diagnostics = List.copyOf(diagnostics);
    }
}
