package io.github.rezabakhshi.embedra.ghidra.nordic;

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
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Program;
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
 * Integration test suite verifying T101: Real-Ghidra GUI & Headless Multi-Program Import Wiring for Nordic.
 */
class NordicFirmwareImportIntegrationTest {

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
        NordicFirmwareLoader loader = new NordicFirmwareLoader();

        // 1. nRF51822 RAW_BINARY
        byte[] nrf51Bin = fixture("nrf51822_app.bin");
        ByteArrayProvider nrf51Prov = new ByteArrayProvider("nrf51822_app.bin", nrf51Bin);
        Collection<LoadSpec> nrf51Specs = loader.findSupportedLoadSpecs(nrf51Prov);
        assertFalse(nrf51Specs.isEmpty(), "Must detect nRF51 raw binary");
        LoadSpec nrf51Spec = nrf51Specs.iterator().next();
        assertEquals("ARM:LE:32:Cortex", nrf51Spec.getLanguageCompilerSpec().getLanguageID().getIdAsString());

        try (LoadResults<? extends DomainObject> res = load(loader, nrf51Prov, nrf51Spec)) {
            res.getPrimary().apply(d -> {
                Program prog = (Program) d;
                assertTrue(prog.getMemory().contains(addr(prog, 0x00000000L)));
                assertTrue(prog.getMemory().contains(addr(prog, 0x20000000L)));
                Address entry = addr(prog, 0x000000C0L);
                assertNotNull(prog.getSymbolTable().getPrimarySymbol(entry));
                assertEquals("Reset_Handler", prog.getSymbolTable().getPrimarySymbol(entry).getName());
            });
        }

        // 2. nRF52832 INTEL_HEX
        byte[] nrf52Hex = fixture("nrf52832_app.hex");
        ByteArrayProvider nrf52Prov = new ByteArrayProvider("nrf52832_app.hex", nrf52Hex);
        Collection<LoadSpec> nrf52Specs = loader.findSupportedLoadSpecs(nrf52Prov);
        assertFalse(nrf52Specs.isEmpty(), "Must detect nRF52 Intel HEX");
        LoadSpec nrf52Spec = nrf52Specs.iterator().next();

        try (LoadResults<? extends DomainObject> res = load(loader, nrf52Prov, nrf52Spec)) {
            res.getPrimary().apply(d -> {
                Program prog = (Program) d;
                assertTrue(prog.getMemory().contains(addr(prog, 0x00000000L)));
                assertTrue(prog.getMemory().contains(addr(prog, 0x20000000L)));
                Address entry = addr(prog, 0x00000100L);
                assertNotNull(prog.getSymbolTable().getPrimarySymbol(entry));
                assertEquals("Reset_Handler", prog.getSymbolTable().getPrimarySymbol(entry).getName());
            });
        }

        // 3. nRF52840 ELF
        byte[] nrf52840Elf = fixture("nrf52840_app.elf");
        ByteArrayProvider nrf52840Prov = new ByteArrayProvider("nrf52840_app.elf", nrf52840Elf);
        Collection<LoadSpec> nrf52840Specs = loader.findSupportedLoadSpecs(nrf52840Prov);
        assertFalse(nrf52840Specs.isEmpty(), "Must detect nRF52840 ELF");
        LoadSpec nrf52840Spec = nrf52840Specs.iterator().next();

        try (LoadResults<? extends DomainObject> res = load(loader, nrf52840Prov, nrf52840Spec)) {
            res.getPrimary().apply(d -> {
                Program prog = (Program) d;
                assertTrue(prog.getMemory().contains(addr(prog, 0x00000000L)));
                assertTrue(prog.getMemory().contains(addr(prog, 0x20000000L)));
                assertTrue(prog.getMemory().contains(addr(prog, 0x5002A000L))); // CC310
                Address entry = addr(prog, 0x00000100L);
                assertNotNull(prog.getSymbolTable().getPrimarySymbol(entry));
                assertEquals("Reset_Handler", prog.getSymbolTable().getPrimarySymbol(entry).getName());
            });
        }
    }

    @Test
    void testUicrConfigurationDataImport() throws Exception {
        NordicFirmwareLoader loader = new NordicFirmwareLoader();
        byte[] uicrHex = fixture("nrf52840_uicr.hex");
        ByteArrayProvider uicrProv = new ByteArrayProvider("nrf52840_uicr.hex", uicrHex);

        Collection<LoadSpec> specs = loader.findSupportedLoadSpecs(uicrProv);
        assertFalse(specs.isEmpty());

        try (LoadResults<? extends DomainObject> res = load(loader, uicrProv, specs.iterator().next())) {
            res.getPrimary().apply(d -> {
                Program prog = (Program) d;
                assertTrue(prog.getMemory().contains(addr(prog, 0x10001000L)));
                Address blAddr = addr(prog, 0x000F8000L);
                assertNotNull(prog.getSymbolTable().getPrimarySymbol(blAddr));
                assertEquals("Bootloader_Reset_Handler", prog.getSymbolTable().getPrimarySymbol(blAddr).getName());
            });
        }
    }

    @Test
    void testMultiImageSoftDeviceAlignment() throws Exception {
        NordicFirmwareLoader loader = new NordicFirmwareLoader();

        // S132 (nRF52832) - Relocated application at 0x00026000
        byte[] s132Hex = fixture("nrf52832_s132_app.hex");
        ByteArrayProvider s132Prov = new ByteArrayProvider("nrf52832_s132_app.hex", s132Hex);
        LoadSpec s132Spec = loader.findSupportedLoadSpecs(s132Prov).iterator().next();

        try (LoadResults<? extends DomainObject> res = load(loader, s132Prov, s132Spec)) {
            res.getPrimary().apply(d -> {
                Program prog = (Program) d;
                assertTrue(prog.getMemory().contains(addr(prog, 0x00000000L)), "MBR at 0x0");
                assertTrue(prog.getMemory().contains(addr(prog, 0x00001000L)), "SoftDevice at 0x1000");
                assertTrue(prog.getMemory().contains(addr(prog, 0x00026000L)), "Relocated App at 0x26000");
                Address appEntry = addr(prog, 0x00026100L);
                assertNotNull(prog.getSymbolTable().getPrimarySymbol(appEntry));
                assertEquals("Application_Reset_Handler", prog.getSymbolTable().getPrimarySymbol(appEntry).getName());
            });
        }

        // S140 (nRF52840) - Relocated application at 0x00027000
        byte[] s140Hex = fixture("nrf52840_s140_app.hex");
        ByteArrayProvider s140Prov = new ByteArrayProvider("nrf52840_s140_app.hex", s140Hex);
        LoadSpec s140Spec = loader.findSupportedLoadSpecs(s140Prov).iterator().next();

        try (LoadResults<? extends DomainObject> res = load(loader, s140Prov, s140Spec)) {
            res.getPrimary().apply(d -> {
                Program prog = (Program) d;
                assertTrue(prog.getMemory().contains(addr(prog, 0x00000000L)), "MBR at 0x0");
                assertTrue(prog.getMemory().contains(addr(prog, 0x00001000L)), "SoftDevice at 0x1000");
                assertTrue(prog.getMemory().contains(addr(prog, 0x00027000L)), "Relocated App at 0x27000");
                Address appEntry = addr(prog, 0x00027100L);
                assertNotNull(prog.getSymbolTable().getPrimarySymbol(appEntry));
                assertEquals("Application_Reset_Handler", prog.getSymbolTable().getPrimarySymbol(appEntry).getName());
            });
        }
    }

    @Test
    void testDualCoreNrf5340PairImport() throws Exception {
        NordicFirmwareImportService service = new NordicFirmwareImportService();
        Language lang = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("ARM:LE:32:Cortex"));
        CompilerSpec comp = lang.getDefaultCompilerSpec();

        ProgramDB appProg = new ProgramDB("nrf5340_app", lang, comp, CONSUMER);
        ProgramDB netProg = new ProgramDB("nrf5340_net", lang, comp, CONSUMER);

        try {
            byte[] appBytes = fixture("nrf5340_app_core.elf");
            byte[] netBytes = fixture("nrf5340_net_core.elf");

            service.importDualCorePair(appProg, appBytes, netProg, netBytes, "nRF5340-QKAA",
                    ParserLimits.defaults(), TaskMonitor.DUMMY);

            // Assert App Core mappings
            assertTrue(appProg.getMemory().contains(addr(appProg, 0x00000000L)), "App Flash");
            assertTrue(appProg.getMemory().contains(addr(appProg, 0x20000000L)), "App RAM");
            assertEquals("Network Core", appProg.getOptions("Embedra Nordic Firmware")
                    .getString("Dual-Core Peer Role", ""));

            // Assert Net Core mappings
            assertTrue(netProg.getMemory().contains(addr(netProg, 0x01000000L)), "Net Flash Global");
            assertTrue(netProg.getMemory().contains(addr(netProg, 0x21000000L)), "Net RAM Global");
            assertEquals("Application Core", netProg.getOptions("Embedra Nordic Firmware")
                    .getString("Dual-Core Peer Role", ""));

            // Assert IPC plate comment
            String appIpcPlate = appProg.getListing().getComment(CommentType.PLATE, addr(appProg, 0x4002A000L));
            assertNotNull(appIpcPlate);
            assertTrue(appIpcPlate.contains("IPC"));
        } finally {
            appProg.release(CONSUMER);
            netProg.release(CONSUMER);
        }
    }

    @Test
    void testTrustZoneNrf9160PairImport() throws Exception {
        NordicFirmwareImportService service = new NordicFirmwareImportService();
        Language lang = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("ARM:LE:32:Cortex"));
        CompilerSpec comp = lang.getDefaultCompilerSpec();

        ProgramDB secProg = new ProgramDB("nrf9160_sec", lang, comp, CONSUMER);
        ProgramDB nsProg = new ProgramDB("nrf9160_ns", lang, comp, CONSUMER);

        try {
            byte[] secBytes = fixture("nrf9160_secure.elf");
            byte[] nsBytes = fixture("nrf9160_nonsecure.elf");

            service.importTrustZonePair(secProg, secBytes, nsProg, nsBytes, "nRF9160-SICA",
                    ParserLimits.defaults(), TaskMonitor.DUMMY);

            // Assert Secure mappings
            assertTrue(secProg.getMemory().contains(addr(secProg, 0x00000000L)), "Secure Flash");
            assertEquals("Non-Secure", secProg.getOptions("Embedra Nordic Firmware")
                    .getString("TrustZone Peer Domain", ""));

            // Assert Non-Secure mappings
            assertTrue(nsProg.getMemory().contains(addr(nsProg, 0x00040000L)), "Non-Secure Flash");
            assertEquals("Secure", nsProg.getOptions("Embedra Nordic Firmware")
                    .getString("TrustZone Peer Domain", ""));
        } finally {
            secProg.release(CONSUMER);
            nsProg.release(CONSUMER);
        }
    }

    @Test
    void testMalformedFixturesFailClosed() throws Exception {
        NordicFirmwareLoader loader = new NordicFirmwareLoader();
        ParserLimits limits = ParserLimits.defaults();

        // 1. Invalid vector
        byte[] invVec = malformedFixture("nrf52_invalid_vector.bin");
        assertTrue(loader.findSupportedLoadSpecs(new ByteArrayProvider("inv.bin", invVec)).isEmpty());
        NordicMappingException ex1 = assertThrows(NordicMappingException.class, () ->
            NordicInputDecoder.decode(invVec, limits));
        assertTrue(ex1.getMessage().contains("INVALID_INITIAL_SP_AND_EVEN_RESET_VECTOR"));

        // 2. Truncated HEX
        byte[] truncHex = malformedFixture("nrf52_truncated.hex");
        assertTrue(loader.findSupportedLoadSpecs(new ByteArrayProvider("tr.hex", truncHex)).isEmpty());
        NordicMappingException ex2 = assertThrows(NordicMappingException.class, () ->
            NordicInputDecoder.decode(truncHex, limits));
        assertTrue(ex2.getMessage().contains("TRUNCATED_INTEL_HEX_RECORD"));

        // 3. Bad Checksum
        byte[] badChk = malformedFixture("nrf52_bad_checksum.hex");
        assertTrue(loader.findSupportedLoadSpecs(new ByteArrayProvider("chk.hex", badChk)).isEmpty());
        NordicMappingException ex3 = assertThrows(NordicMappingException.class, () ->
            NordicInputDecoder.decode(badChk, limits));
        assertTrue(ex3.getMessage().contains("CHECKSUM_MISMATCH"));

        // 4. Overlapping HEX
        byte[] overlap = malformedFixture("nrf52_overlapping.hex");
        assertTrue(loader.findSupportedLoadSpecs(new ByteArrayProvider("ov.hex", overlap)).isEmpty());
        NordicMappingException ex4 = assertThrows(NordicMappingException.class, () ->
            NordicInputDecoder.decode(overlap, limits));
        assertTrue(ex4.getMessage().contains("OVERLAPPING_MEMORY_SEGMENTS"));

        // 5. Truncated ELF
        byte[] truncElf = malformedFixture("nrf52_truncated_elf.elf");
        assertTrue(loader.findSupportedLoadSpecs(new ByteArrayProvider("tr.elf", truncElf)).isEmpty());
        NordicMappingException ex5 = assertThrows(NordicMappingException.class, () ->
            NordicInputDecoder.decode(truncElf, limits));
        assertTrue(ex5.getMessage().contains("TRUNCATED_ELF_FILE"));
    }

    @Test
    void testCancellationRollsBackCleanly() throws Exception {
        NordicFirmwareImportService service = new NordicFirmwareImportService();
        Language lang = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("ARM:LE:32:Cortex"));
        CompilerSpec comp = lang.getDefaultCompilerSpec();
        ProgramDB prog = new ProgramDB("cancel_test", lang, comp, CONSUMER);

        CancellingMonitor monitor = new CancellingMonitor();
        monitor.cancel();

        try {
            byte[] nrf52Hex = fixture("nrf52832_app.hex");
            assertThrows(CancelledException.class, () ->
                service.importFirmware(prog, nrf52Hex, "nRF52832-QFAA", ParserLimits.defaults(), monitor));

            assertEquals(0, prog.getMemory().getBlocks().length, "Memory must be clean after rollback");
        } finally {
            prog.release(CONSUMER);
        }
    }

    @Test
    void testGuiAndHeadlessParity() throws Exception {
        NordicFirmwareLoader loader = new NordicFirmwareLoader();
        byte[] elfBytes = fixture("nrf52840_app.elf");
        ByteArrayProvider prov = new ByteArrayProvider("nrf52840_app.elf", elfBytes);
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

    private static Address addr(Program program, long offset) {
        return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
    }

    private static Program loadProgram(
            NordicFirmwareLoader loader,
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
            NordicFirmwareLoader loader,
            ByteArrayProvider provider,
            LoadSpec spec) throws Exception {
        List<Option> opts = loader.getDefaultOptions(provider, spec, null, false, false);
        ImporterSettings settings = new ImporterSettings(
                provider, provider.getName(), null,
                "/", false, spec, opts, CONSUMER, new MessageLog(), TaskMonitor.DUMMY);
        return loader.load(settings);
    }

    private static byte[] fixture(String name) throws IOException {
        String path = "/fixtures/nordic/" + name;
        try (InputStream input = NordicFirmwareImportIntegrationTest.class.getResourceAsStream(path)) {
            assertNotNull(input, "missing fixture " + path);
            return input.readAllBytes();
        }
    }

    private static byte[] malformedFixture(String name) throws IOException {
        String path = "/fixtures/nordic/malformed/" + name;
        try (InputStream input = NordicFirmwareImportIntegrationTest.class.getResourceAsStream(path)) {
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
