package io.github.rezabakhshi.embedra.ghidra.atmel;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ghidra.GhidraApplicationLayout;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.LoadResults;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.Loader.ImporterSettings;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.framework.model.DomainObject;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.ghidra.equivalence.GhidraProgramEquivalenceAssertor;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.TimeZone;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Integration test suite verifying T109: Real-Ghidra GUI & Headless Multi-Program Import Wiring for Atmel.
 */
class AtmelFirmwareImportIntegrationTest {

    private static final Object CONSUMER = new Object();

    @BeforeAll
    static void initializeGhidraApplication() throws Exception {
        if (!Application.isInitialized()) {
            ApplicationConfiguration configuration = new ApplicationConfiguration();
            configuration.setInitializeLogging(false);
            Application.initializeApplication(
                    new GhidraApplicationLayout(new File(System.getenv("GHIDRA_INSTALL_DIR"))),
                    configuration);
        }
        DefaultLanguageService.getLanguageService().getLanguageDescriptions(true);
    }

    @Test
    void testSingleImageBaremetalImports() throws Exception {
        AtmelFirmwareLoader loader = new AtmelFirmwareLoader();

        // 1. ATmega328P RAW_BINARY
        byte[] atmega328Bin = fixture("atmega328p_app.bin");
        ByteArrayProvider atmega328Prov = new ByteArrayProvider("atmega328p_app.bin", atmega328Bin);
        Collection<LoadSpec> atmega328Specs = loader.findSupportedLoadSpecs(atmega328Prov);
        assertFalse(atmega328Specs.isEmpty(), "Must detect ATmega328P raw binary");
        LoadSpec atmega328Spec = atmega328Specs.iterator().next();
        assertEquals("avr8:LE:16:default", atmega328Spec.getLanguageCompilerSpec().getLanguageID().getIdAsString());

        try (LoadResults<? extends DomainObject> res = load(loader, atmega328Prov, atmega328Spec)) {
            res.getPrimary().apply(d -> {
                Program prog = (Program) d;
                AddressSpace codeSpace = prog.getAddressFactory().getAddressSpace("code");
                assertNotNull(codeSpace);
                assertTrue(prog.getMemory().contains(codeSpace.getAddress(0x0000L)));
                Address entry = codeSpace.getAddress(0x0034L); // 0x0068 / 2
                assertNotNull(prog.getSymbolTable().getPrimarySymbol(entry));
                assertEquals("Reset_Handler", prog.getSymbolTable().getPrimarySymbol(entry).getName());
            });
        }

        // 2. ATmega328P INTEL_HEX
        byte[] atmega328Hex = fixture("atmega328p_app.hex");
        ByteArrayProvider atmega328HexProv = new ByteArrayProvider("atmega328p_app.hex", atmega328Hex);
        Collection<LoadSpec> atmega328HexSpecs = loader.findSupportedLoadSpecs(atmega328HexProv);
        assertFalse(atmega328HexSpecs.isEmpty(), "Must detect ATmega328P Intel HEX");
        LoadSpec atmega328HexSpec = atmega328HexSpecs.iterator().next();

        try (LoadResults<? extends DomainObject> res = load(loader, atmega328HexProv, atmega328HexSpec)) {
            res.getPrimary().apply(d -> {
                Program prog = (Program) d;
                AddressSpace codeSpace = prog.getAddressFactory().getAddressSpace("code");
                assertTrue(prog.getMemory().contains(codeSpace.getAddress(0x0000L)));
                Address entry = codeSpace.getAddress(0x0034L);
                assertNotNull(prog.getSymbolTable().getPrimarySymbol(entry));
                assertEquals("Reset_Handler", prog.getSymbolTable().getPrimarySymbol(entry).getName());
            });
        }

        // 3. ATmega328P ELF
        byte[] atmega328Elf = fixture("atmega328p_app.elf");
        ByteArrayProvider atmega328ElfProv = new ByteArrayProvider("atmega328p_app.elf", atmega328Elf);
        Collection<LoadSpec> atmega328ElfSpecs = loader.findSupportedLoadSpecs(atmega328ElfProv);
        assertFalse(atmega328ElfSpecs.isEmpty(), "Must detect ATmega328P ELF");
        LoadSpec atmega328ElfSpec = atmega328ElfSpecs.iterator().next();

        try (LoadResults<? extends DomainObject> res = load(loader, atmega328ElfProv, atmega328ElfSpec)) {
            res.getPrimary().apply(d -> {
                Program prog = (Program) d;
                AddressSpace codeSpace = prog.getAddressFactory().getAddressSpace("code");
                assertTrue(prog.getMemory().contains(codeSpace.getAddress(0x0000L)));
                Address entry = codeSpace.getAddress(0x0034L);
                assertNotNull(prog.getSymbolTable().getPrimarySymbol(entry));
                assertEquals("Reset_Handler", prog.getSymbolTable().getPrimarySymbol(entry).getName());
            });
        }

        // 4. ATmega2560 (Flash > 64KB -> avr8:LE:16:atmega256)
        byte[] atmega2560Bin = fixture("atmega2560_app.bin");
        ByteArrayProvider atmega2560Prov = new ByteArrayProvider("atmega2560_app.bin", atmega2560Bin);
        Collection<LoadSpec> atmega2560Specs = loader.findSupportedLoadSpecs(atmega2560Prov);
        assertFalse(atmega2560Specs.isEmpty(), "Must detect ATmega2560 raw binary");

        LoadSpec spec2560 = atmega2560Specs.iterator().next();
        try (LoadResults<? extends DomainObject> res = load(loader, atmega2560Prov, spec2560)) {
            res.getPrimary().apply(d -> {
                Program prog = (Program) d;
                AddressSpace codeSpace = prog.getAddressFactory().getAddressSpace("code");
                assertTrue(prog.getMemory().contains(codeSpace.getAddress(0x0000L)));
                Address entry = codeSpace.getAddress(0x0072L); // 0x00e4 / 2
                assertNotNull(prog.getSymbolTable().getPrimarySymbol(entry));
                assertEquals("Reset_Handler", prog.getSymbolTable().getPrimarySymbol(entry).getName());
            });
        }

        // 5. ATtiny85 (RJMP vector)
        byte[] attiny85Bin = fixture("attiny85_app.bin");
        ByteArrayProvider attiny85Prov = new ByteArrayProvider("attiny85_app.bin", attiny85Bin);
        Collection<LoadSpec> attiny85Specs = loader.findSupportedLoadSpecs(attiny85Prov);
        assertFalse(attiny85Specs.isEmpty(), "Must detect ATtiny85 raw binary");

        try (LoadResults<? extends DomainObject> res = load(loader, attiny85Prov, attiny85Specs.iterator().next())) {
            res.getPrimary().apply(d -> {
                Program prog = (Program) d;
                AddressSpace codeSpace = prog.getAddressFactory().getAddressSpace("code");
                assertTrue(prog.getMemory().contains(codeSpace.getAddress(0x0000L)));
                Address entry = codeSpace.getAddress(0x000FL); // 0x001E / 2
                assertNotNull(prog.getSymbolTable().getPrimarySymbol(entry));
                assertEquals("Reset_Handler", prog.getSymbolTable().getPrimarySymbol(entry).getName());
            });
        }

        // 6. SAMD21G18A (ARM Cortex-M0+)
        byte[] samd21Bin = fixture("samd21g18a_app.bin");
        ByteArrayProvider samd21Prov = new ByteArrayProvider("samd21g18a_app.bin", samd21Bin);
        Collection<LoadSpec> samd21Specs = loader.findSupportedLoadSpecs(samd21Prov);
        assertFalse(samd21Specs.isEmpty(), "Must detect SAMD21 raw binary");
        LoadSpec samd21Spec = samd21Specs.iterator().next();
        assertEquals("ARM:LE:32:Cortex", samd21Spec.getLanguageCompilerSpec().getLanguageID().getIdAsString());

        try (LoadResults<? extends DomainObject> res = load(loader, samd21Prov, samd21Spec)) {
            res.getPrimary().apply(d -> {
                Program prog = (Program) d;
                assertTrue(prog.getMemory().contains(addr(prog, 0x00000000L)));
                assertTrue(prog.getMemory().contains(addr(prog, 0x20000000L)));
                Address entry = addr(prog, 0x000000C0L);
                assertNotNull(prog.getSymbolTable().getPrimarySymbol(entry));
                assertEquals("Reset_Handler", prog.getSymbolTable().getPrimarySymbol(entry).getName());
            });
        }

        // 7. SAME70Q21 (ARM Cortex-M7 at 0x00400000)
        byte[] same70Hex = fixture("same70q21_app.hex");
        ByteArrayProvider same70Prov = new ByteArrayProvider("same70q21_app.hex", same70Hex);
        Collection<LoadSpec> same70Specs = loader.findSupportedLoadSpecs(same70Prov);
        assertFalse(same70Specs.isEmpty(), "Must detect SAME70 Intel HEX");

        try (LoadResults<? extends DomainObject> res = load(loader, same70Prov, same70Specs.iterator().next())) {
            res.getPrimary().apply(d -> {
                Program prog = (Program) d;
                assertTrue(prog.getMemory().contains(addr(prog, 0x00400000L)));
                assertTrue(prog.getMemory().contains(addr(prog, 0x20400000L)));
                Address entry = addr(prog, 0x00400200L);
                assertNotNull(prog.getSymbolTable().getPrimarySymbol(entry));
                assertEquals("Reset_Handler", prog.getSymbolTable().getPrimarySymbol(entry).getName());
            });
        }
    }

    @Test
    void testCompositeAndBootloaderImages() throws Exception {
        AtmelFirmwareLoader loader = new AtmelFirmwareLoader();

        // 1. ATmega328P composite HEX (App at 0x0000 + Optiboot at 0x7E00)
        byte[] compositeHex = fixture("atmega328p_composite.hex");
        ByteArrayProvider compProv = new ByteArrayProvider("atmega328p_composite.hex", compositeHex);
        LoadSpec compSpec = loader.findSupportedLoadSpecs(compProv).iterator().next();

        try (LoadResults<? extends DomainObject> res = load(loader, compProv, compSpec)) {
            res.getPrimary().apply(d -> {
                Program prog = (Program) d;
                AddressSpace codeSpace = prog.getAddressFactory().getAddressSpace("code");
                // App entry at 0x0034 (word)
                Address appEntry = codeSpace.getAddress(0x0034L);
                assertNotNull(prog.getSymbolTable().getPrimarySymbol(appEntry));
                assertEquals("Reset_Handler", prog.getSymbolTable().getPrimarySymbol(appEntry).getName());

                // Bootloader entry at 0x3F00 (word for byte 0x7E00)
                Address bootEntry = codeSpace.getAddress(0x3F00L);
                assertNotNull(prog.getSymbolTable().getPrimarySymbol(bootEntry));
                assertEquals("Optiboot_Reset_Handler", prog.getSymbolTable().getPrimarySymbol(bootEntry).getName());
            });
        }

        // 2. SAME70 SAM-BA ROM bootloader (at 0x00800000)
        byte[] sambaHex = fixture("same70q21_samba.hex");
        ByteArrayProvider sambaProv = new ByteArrayProvider("same70q21_samba.hex", sambaHex);
        LoadSpec sambaSpec = loader.findSupportedLoadSpecs(sambaProv).iterator().next();

        try (LoadResults<? extends DomainObject> res = load(loader, sambaProv, sambaSpec)) {
            res.getPrimary().apply(d -> {
                Program prog = (Program) d;
                assertTrue(prog.getMemory().contains(addr(prog, 0x00800000L)));
                Address sambaEntry = addr(prog, 0x00800000L);
                assertNotNull(prog.getSymbolTable().getPrimarySymbol(sambaEntry));
                assertEquals("SAMBA_Reset_Handler", prog.getSymbolTable().getPrimarySymbol(sambaEntry).getName());
            });
        }
    }

    @Test
    void testMalformedFixturesFailClosed() throws Exception {
        AtmelFirmwareLoader loader = new AtmelFirmwareLoader();
        ParserLimits limits = ParserLimits.defaults();

        // 1. Invalid AVR vector table
        byte[] invVec = malformedFixture("attiny85_invalid_vector.bin");
        assertTrue(loader.findSupportedLoadSpecs(new ByteArrayProvider("inv.bin", invVec)).isEmpty());
        AtmelMappingException ex1 = assertThrows(AtmelMappingException.class, () ->
            AtmelInputDecoder.decode(invVec, limits));
        assertTrue(ex1.getMessage().contains("INVALID_AVR_VECTOR_TABLE"));

        // 2. SAM invalid initial stack pointer
        byte[] badSp = malformedFixture("samd21_bad_sp.bin");
        assertTrue(loader.findSupportedLoadSpecs(new ByteArrayProvider("bad_sp.bin", badSp)).isEmpty());
        AtmelMappingException ex2 = assertThrows(AtmelMappingException.class, () ->
            AtmelInputDecoder.decode(badSp, limits));
        assertTrue(ex2.getMessage().contains("INVALID_INITIAL_SP"));

        // 3. Truncated ARM binary vector table
        byte[] truncBin = malformedFixture("same70_truncated.bin");
        assertTrue(loader.findSupportedLoadSpecs(new ByteArrayProvider("trunc.bin", truncBin)).isEmpty());
        AtmelMappingException ex3 = assertThrows(AtmelMappingException.class, () ->
            AtmelInputDecoder.decode(truncBin, limits));
        assertTrue(ex3.getMessage().contains("BINARY_TRUNCATED_VECTOR_TABLE"));

        // 4. Truncated HEX record
        byte[] truncHex = malformedFixture("atmel_truncated.hex");
        assertTrue(loader.findSupportedLoadSpecs(new ByteArrayProvider("tr.hex", truncHex)).isEmpty());
        AtmelMappingException ex4 = assertThrows(AtmelMappingException.class, () ->
            AtmelInputDecoder.decode(truncHex, limits));
        assertTrue(ex4.getMessage().contains("HEX_UNEXPECTED_EOF"));

        // 5. Bad Checksum in HEX
        byte[] badChk = malformedFixture("atmel_bad_checksum.hex");
        assertTrue(loader.findSupportedLoadSpecs(new ByteArrayProvider("chk.hex", badChk)).isEmpty());
        AtmelMappingException ex5 = assertThrows(AtmelMappingException.class, () ->
            AtmelInputDecoder.decode(badChk, limits));
        assertTrue(ex5.getMessage().contains("HEX_CHECKSUM_MISMATCH"));

        // 6. Overlapping HEX with conflicting data
        byte[] overlap = malformedFixture("atmel_overlapping.hex");
        assertTrue(loader.findSupportedLoadSpecs(new ByteArrayProvider("ov.hex", overlap)).isEmpty());
        AtmelMappingException ex6 = assertThrows(AtmelMappingException.class, () ->
            AtmelInputDecoder.decode(overlap, limits));
        assertTrue(ex6.getMessage().contains("MEMORY_OVERLAP_CONFLICT"),
            "Actual message was: " + ex6.getMessage());

        // 7. Truncated ELF header
        byte[] truncElf = malformedFixture("atmega328p_truncated_elf.elf");
        assertTrue(loader.findSupportedLoadSpecs(new ByteArrayProvider("tr.elf", truncElf)).isEmpty());
        AtmelMappingException ex7 = assertThrows(AtmelMappingException.class, () ->
            AtmelInputDecoder.decode(truncElf, limits));
        assertTrue(ex7.getMessage().contains("ELF_TRUNCATED_HEADER"));
    }

    @Test
    void testCancellationRollsBackCleanly() throws Exception {
        AtmelFirmwareImportService service = new AtmelFirmwareImportService();
        Language lang = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("avr8:LE:16:default"));
        CompilerSpec comp = lang.getDefaultCompilerSpec();
        ProgramDB prog = new ProgramDB("cancel_test", lang, comp, CONSUMER);

        CancellingMonitor monitor = new CancellingMonitor();
        monitor.cancel();

        try {
            byte[] hex = fixture("atmega328p_app.hex");
            assertThrows(CancelledException.class, () ->
                service.importFirmware(prog, hex, "ATmega328P", ParserLimits.defaults(), monitor));

            assertEquals(0, prog.getMemory().getBlocks().length, "Memory must be clean after rollback");
        } finally {
            prog.release(CONSUMER);
        }
    }

    @Test
    void testGuiAndHeadlessParity() throws Exception {
        AtmelFirmwareLoader loader = new AtmelFirmwareLoader();
        byte[] elfBytes = fixture("atmega328p_app.elf");
        ByteArrayProvider prov = new ByteArrayProvider("atmega328p_app.elf", elfBytes);
        LoadSpec spec = loader.findSupportedLoadSpecs(prov).iterator().next();

        Object guiConsumer = new Object();
        Object headlessConsumer = new Object();
        Locale origLoc = Locale.getDefault();
        TimeZone origTz = TimeZone.getDefault();

        try {
            Locale.setDefault(Locale.US);
            TimeZone.setDefault(TimeZone.getTimeZone("UTC"));
            Program guiProg = loadProgram(loader, prov, spec, guiConsumer);

            Locale.setDefault(Locale.JAPAN);
            TimeZone.setDefault(TimeZone.getTimeZone("Pacific/Auckland"));
            Program headlessProg = loadProgram(loader, prov, spec, headlessConsumer);

            try {
                GhidraProgramEquivalenceAssertor.assertProgramEquivalence(guiProg, headlessProg);
            } finally {
                guiProg.release(guiConsumer);
                headlessProg.release(headlessConsumer);
            }
        } finally {
            Locale.setDefault(origLoc);
            TimeZone.setDefault(origTz);
        }
    }

    @Test
    void testUserArtifactPreservation() throws Exception {
        AtmelFirmwareImportService service = new AtmelFirmwareImportService();
        Language lang = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("avr8:LE:16:default"));
        CompilerSpec comp = lang.getDefaultCompilerSpec();
        ProgramDB prog = new ProgramDB("preservation_test", lang, comp, CONSUMER);

        try {
            int tx = prog.startTransaction("User annotation");
            AddressSpace codeSpace = prog.getAddressFactory().getAddressSpace("code");
            Address userAddr = codeSpace.getAddress(0x0034L);
            prog.getListing().setComment(userAddr, CommentType.PRE, "User analysis note: critical routine");
            prog.getSymbolTable().createLabel(userAddr, "UserSpecialRoutine", SourceType.USER_DEFINED);
            prog.endTransaction(tx, true);

            byte[] hex = fixture("atmega328p_app.hex");
            service.importFirmware(prog, hex, "ATmega328P", ParserLimits.defaults(), TaskMonitor.DUMMY);

            assertEquals("User analysis note: critical routine",
                prog.getListing().getComment(CommentType.PRE, userAddr));
            assertNotNull(prog.getSymbolTable().getGlobalSymbols("UserSpecialRoutine"));
            assertFalse(prog.getSymbolTable().getGlobalSymbols("UserSpecialRoutine").isEmpty());
        } finally {
            prog.release(CONSUMER);
        }
    }

    private static Address addr(Program program, long offset) {
        return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
    }

    private static Program loadProgram(
            AtmelFirmwareLoader loader,
            ByteArrayProvider provider,
            LoadSpec spec,
            Object consumer) throws Exception {
        List<Option> opts = loader.getDefaultOptions(provider, spec, null, false, false);
        ImporterSettings settings = new ImporterSettings(
                provider, provider.getName(), null,
                "/", false, spec, opts, consumer, new MessageLog(), TaskMonitor.DUMMY);
        LoadResults<? extends DomainObject> results = loader.load(settings);
        Program[] holder = new Program[1];
        results.getPrimary().apply(d -> holder[0] = (Program) d);
        return holder[0];
    }

    private static LoadResults<? extends DomainObject> load(
            AtmelFirmwareLoader loader,
            ByteArrayProvider provider,
            LoadSpec spec) throws Exception {
        List<Option> opts = loader.getDefaultOptions(provider, spec, null, false, false);
        ImporterSettings settings = new ImporterSettings(
                provider, provider.getName(), null,
                "/", false, spec, opts, CONSUMER, new MessageLog(), TaskMonitor.DUMMY);
        return loader.load(settings);
    }

    private static byte[] fixture(String name) throws IOException {
        String path = "/fixtures/atmel/" + name;
        try (InputStream input = AtmelFirmwareImportIntegrationTest.class.getResourceAsStream(path)) {
            assertNotNull(input, "missing fixture " + path);
            return input.readAllBytes();
        }
    }

    private static byte[] malformedFixture(String name) throws IOException {
        String path = "/fixtures/atmel/malformed/" + name;
        try (InputStream input = AtmelFirmwareImportIntegrationTest.class.getResourceAsStream(path)) {
            assertNotNull(input, "missing malformed fixture " + path);
            return input.readAllBytes();
        }
    }

    private static final class CancellingMonitor extends TaskMonitorAdapter {
        private boolean cancelled;

        @Override
        public boolean isCancelled() {
            return cancelled;
        }

        @Override
        public void checkCancelled() throws CancelledException {
            if (cancelled) {
                throw new CancelledException();
            }
        }

        public void cancel() {
            this.cancelled = true;
        }
    }
}
