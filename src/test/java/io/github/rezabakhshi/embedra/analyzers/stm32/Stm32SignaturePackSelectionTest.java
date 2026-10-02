package io.github.rezabakhshi.embedra.analyzers.stm32;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.pack.LocalPackRepository;
import io.github.rezabakhshi.embedra.pack.PackRequirement;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class Stm32SignaturePackSelectionTest {
    private static final Path SHIPPED = Path.of("packs/stm32.stm32f1.signatures/1.0.0");

    @TempDir
    Path temporary;

    @Test
    void installsSelectsAndLoadsCommittedPack() throws Exception {
        LocalPackRepository repository = new LocalPackRepository(
            Files.createDirectory(temporary.resolve("repo")), ParserLimits.defaults());
        repository.install(SHIPPED, CancellationToken.none());
        Stm32SignaturePack pack = Stm32SignaturePackSelection.select(repository,
            new PackRequirement(Stm32SignaturePackLoader.PACK_ID, Optional.empty(),
                Optional.of(Stm32SignaturePackLoader.SERIES)),
            ParserLimits.defaults(), CancellationToken.none());
        assertEquals(Stm32SignaturePackLoader.PACK_ID, pack.manifest().packId());
        assertEquals(1543, pack.signatures().size());
    }

    @Test
    void rejectsMissingAndIncompatibleSelection() throws Exception {
        LocalPackRepository repository = new LocalPackRepository(
            Files.createDirectory(temporary.resolve("empty")), ParserLimits.defaults());
        DiagnosticException missing = assertThrows(DiagnosticException.class,
            () -> repository.select(new PackRequirement(Stm32SignaturePackLoader.PACK_ID,
                Optional.empty(), Optional.empty()), CancellationToken.none()));
        assertEquals(DiagnosticCode.PACK_NOT_FOUND, missing.diagnostic().code());

        repository.install(SHIPPED, CancellationToken.none());
        DiagnosticException incompatible = assertThrows(DiagnosticException.class,
            () -> repository.select(new PackRequirement(Stm32SignaturePackLoader.PACK_ID,
                Optional.empty(), Optional.of("STM32F4")), CancellationToken.none()));
        assertEquals(DiagnosticCode.PACK_INCOMPATIBLE, incompatible.diagnostic().code());
    }
}
