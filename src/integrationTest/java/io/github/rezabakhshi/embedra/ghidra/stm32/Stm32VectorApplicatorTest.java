package io.github.rezabakhshi.embedra.ghidra.stm32;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import ghidra.GhidraApplicationLayout;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.stm32.input.Stm32RawBinPlan;
import io.github.rezabakhshi.embedra.core.stm32.input.Stm32VectorDiscovery;
import io.github.rezabakhshi.embedra.targets.stm32.catalog.Stm32CuratedPartIds;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.util.List;
import java.util.Objects;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class Stm32VectorApplicatorTest {
    private static final Object CONSUMER = new Object();

    private static final long BASE = 0x08000000L;

    private ProgramDB program;

    @BeforeAll
    static void initializeGhidra() throws Exception {
        if (!Application.isInitialized()) {
            ApplicationConfiguration configuration = new ApplicationConfiguration();
            configuration.setInitializeLogging(false);
            Application.initializeApplication(new GhidraApplicationLayout(
                new File(System.getenv("GHIDRA_INSTALL_DIR"))), configuration);
        }
    }

    @BeforeEach
    void setUp() throws Exception {
        var language = DefaultLanguageService.getLanguageService().getLanguage(
            new LanguageID("ARM:LE:32:Cortex"));
        program = new ProgramDB("STM32 vector test", language,
            language.getCompilerSpecByID(new CompilerSpecID("default")), CONSUMER);
    }

    @AfterEach
    void tearDown() {
        program.release(CONSUMER);
    }

    @Test
    void createsOnlyConfirmedVectorWordsAndIsIdempotent() throws Exception {
        byte[] bytes = fixture();
        var parts = Stm32CuratedPartIds.load(Path.of(
            "catalogs/stm32/2026-09-29/selection.json"), ParserLimits.defaults(),
            CancellationToken.none());
        var plan = Stm32RawBinPlan.explicit("STM32F103C8T6", BASE,
            bytes.length, parts, ParserLimits.defaults());
        Stm32RawBinImporter.importInto(program,
            new ByteArrayProvider("firmware.bin", bytes), plan, parts, TaskMonitor.DUMMY);
        var candidates = Stm32VectorDiscovery.discover(bytes, BASE,
            List.of(new Stm32VectorDiscovery.AddressRange(0x20000000L, 0x20005000L)),
            ParserLimits.defaults(), CancellationToken.none());
        assertEquals(1, candidates.size());
        assertThrows(IllegalArgumentException.class,
            () -> Stm32VectorDiscovery.confirm(candidates, BASE + 4));
        var confirmed = Stm32VectorDiscovery.confirm(candidates, BASE);
        Stm32VectorApplicator.apply(program, confirmed, TaskMonitor.DUMMY);
        Stm32VectorApplicator.apply(program, confirmed, TaskMonitor.DUMMY);
        assertNotNull(program.getListing().getDefinedDataAt(program.getAddressFactory()
            .getDefaultAddressSpace().getAddress(BASE)));
        assertEquals(BASE, program.getOptions(Stm32VectorApplicator.PROVENANCE_OPTIONS)
            .getLong("Confirmed Vector Address", -1));
        assertEquals("USER_CONFIRMED", program.getOptions(
            Stm32VectorApplicator.PROVENANCE_OPTIONS).getString("Selection", ""));
    }

    @Test
    void changedMappedBytesRejectConfirmationWithoutCreatingVector() throws Exception {
        byte[] bytes = fixture();
        var parts = Stm32CuratedPartIds.load(Path.of(
            "catalogs/stm32/2026-09-29/selection.json"), ParserLimits.defaults(),
            CancellationToken.none());
        var plan = Stm32RawBinPlan.explicit("STM32F103C8T6", BASE,
            bytes.length, parts, ParserLimits.defaults());
        Stm32RawBinImporter.importInto(program,
            new ByteArrayProvider("firmware.bin", bytes), plan, parts, TaskMonitor.DUMMY);
        var candidates = Stm32VectorDiscovery.discover(bytes, BASE,
            List.of(new Stm32VectorDiscovery.AddressRange(0x20000000L, 0x20005000L)),
            ParserLimits.defaults(), CancellationToken.none());
        var confirmed = Stm32VectorDiscovery.confirm(candidates, BASE);
        var address = program.getAddressFactory().getDefaultAddressSpace().getAddress(BASE);
        int transaction = program.startTransaction("Test mapped-byte conflict");
        try {
            program.getMemory().setByte(address, (byte) 0x01);
        }
        finally {
            program.endTransaction(transaction, true);
        }
        assertThrows(IOException.class,
            () -> Stm32VectorApplicator.apply(program, confirmed, TaskMonitor.DUMMY));
        assertNull(program.getListing().getDefinedDataAt(address));
        assertEquals(-1, program.getOptions(Stm32VectorApplicator.PROVENANCE_OPTIONS)
            .getLong("Confirmed Vector Address", -1));
    }

    private byte[] fixture() throws IOException {
        try (InputStream input = Objects.requireNonNull(getClass().getResourceAsStream(
                "/fixtures/stm32f103/STM32F103C8T6.bin"))) {
            return input.readAllBytes();
        }
    }
}
