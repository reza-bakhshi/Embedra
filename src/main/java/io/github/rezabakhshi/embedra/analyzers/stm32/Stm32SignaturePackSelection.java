package io.github.rezabakhshi.embedra.analyzers.stm32;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.pack.InstalledPack;
import io.github.rezabakhshi.embedra.pack.LocalPackRepository;
import io.github.rezabakhshi.embedra.pack.PackRequirement;
import java.util.Objects;

/**
 * Wires STM32 signature matching through the shared offline pack-selection path.
 *
 * <p>The shared repository performs integrity-first, highest-compatible local
 * selection with no network access; the loader then re-verifies the selected
 * pack identity, provenance, digest, and closed content schema before any
 * signature is returned.</p>
 */
public final class Stm32SignaturePackSelection {
    private Stm32SignaturePackSelection() {
    }

    public static Stm32SignaturePack select(LocalPackRepository repository,
            PackRequirement requirement, ParserLimits limits, CancellationToken token)
            throws DiagnosticException {
        Objects.requireNonNull(repository, "repository");
        Objects.requireNonNull(requirement, "requirement");
        InstalledPack installed = repository.select(requirement, token);
        return Stm32SignaturePackLoader.load(installed.directory(), limits, token);
    }
}
