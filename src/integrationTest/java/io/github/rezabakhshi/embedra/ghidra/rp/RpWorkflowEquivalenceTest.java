package io.github.rezabakhshi.embedra.ghidra.rp;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
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
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.util.task.TaskMonitor;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.TimeZone;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class RpWorkflowEquivalenceTest {

    private static final Object GUI_CONSUMER = new Object();

    private static final Object HEADLESS_CONSUMER = new Object();

    @BeforeAll
    static void initializeGhidraApplication() throws Exception {
        if (!Application.isInitialized()) {
            ApplicationConfiguration configuration = new ApplicationConfiguration();
            configuration.setInitializeLogging(false);
            Application.initializeApplication(
                    new GhidraApplicationLayout(new File(System.getenv("GHIDRA_INSTALL_DIR"))),
                    configuration);
        }
    }

    @Test
    void testRp2040GuiAndHeadlessEquivalence() throws Exception {
        assertEquivalenceForFixture("rp/rp2040-pico-blinky.uf2");
    }

    @Test
    void testRp2350ArmGuiAndHeadlessEquivalence() throws Exception {
        assertEquivalenceForFixture("rp/rp2350-arm-pico2.uf2");
    }

    @Test
    void testRp2350RiscvGuiAndHeadlessEquivalence() throws Exception {
        assertEquivalenceForFixture("rp/rp2350-riscv-pico2.uf2");
    }

    private void assertEquivalenceForFixture(String fixtureRelPath) throws Exception {
        byte[] input = fixture(fixtureRelPath);
        RpFirmwareLoader loader = new RpFirmwareLoader();
        ByteArrayProvider provider = new ByteArrayProvider(fixtureRelPath, input);
        Collection<LoadSpec> specs = loader.findSupportedLoadSpecs(provider);
        assertTrue(!specs.isEmpty(), "Should find load specs for " + fixtureRelPath);
        LoadSpec spec = specs.iterator().next();

        List<Option> guiOpts = loader.getDefaultOptions(provider, spec, null, false, false);
        List<Option> headlessOpts = loader.getDefaultOptions(provider, spec, null, false, false);

        Locale origLocale = Locale.getDefault();
        TimeZone origTz = TimeZone.getDefault();

        try {
            // 1. Simulate GUI Interactive Import
            Locale.setDefault(Locale.US);
            TimeZone.setDefault(TimeZone.getTimeZone("UTC"));
            Program guiProgram = loadProgram(loader, provider, spec, guiOpts, GUI_CONSUMER);

            // 2. Simulate Headless Batch Import
            Locale.setDefault(Locale.JAPAN);
            TimeZone.setDefault(TimeZone.getTimeZone("Asia/Tokyo"));
            Program headlessProgram = loadProgram(loader, provider, spec, headlessOpts, HEADLESS_CONSUMER);

            try {
                // Assert byte-for-byte and symbol-for-symbol equivalence
                assertProgramEquivalence(guiProgram, headlessProgram);
            } finally {
                guiProgram.release(GUI_CONSUMER);
                headlessProgram.release(HEADLESS_CONSUMER);
            }
        } finally {
            Locale.setDefault(origLocale);
            TimeZone.setDefault(origTz);
        }
    }

    private static Program loadProgram(
            RpFirmwareLoader loader,
            ByteArrayProvider provider,
            LoadSpec spec,
            List<Option> options,
            Object consumer) throws Exception {
        ImporterSettings settings = new ImporterSettings(
                provider, provider.getName(), null,
                "/", false, spec, options, consumer, new MessageLog(), TaskMonitor.DUMMY);
        LoadResults<? extends DomainObject> results = loader.load(settings);
        final Program[] progRef = new Program[1];
        results.getPrimary().apply(d -> progRef[0] = (Program) d);
        return progRef[0];
    }

    private static void assertProgramEquivalence(Program gui, Program headless) throws Exception {
        // 1. Memory blocks equivalence (count, names, ranges, permissions, byte contents)
        MemoryBlock[] guiBlocks = gui.getMemory().getBlocks();
        MemoryBlock[] headlessBlocks = headless.getMemory().getBlocks();
        assertEquals(guiBlocks.length, headlessBlocks.length, "Memory block count must match");

        for (int i = 0; i < guiBlocks.length; i++) {
            MemoryBlock g = guiBlocks[i];
            MemoryBlock h = headlessBlocks[i];
            assertEquals(g.getName(), h.getName(), "Block name mismatch at " + i);
            assertEquals(g.getStart(), h.getStart(), "Block start mismatch for " + g.getName());
            assertEquals(g.getEnd(), h.getEnd(), "Block end mismatch for " + g.getName());
            assertEquals(g.getSize(), h.getSize(), "Block size mismatch for " + g.getName());
            assertEquals(g.isRead(), h.isRead(), "Block read permission mismatch for " + g.getName());
            assertEquals(g.isWrite(), h.isWrite(), "Block write permission mismatch for " + g.getName());
            assertEquals(g.isExecute(), h.isExecute(), "Block execute permission mismatch for " + g.getName());
            assertEquals(g.isVolatile(), h.isVolatile(), "Block volatile mismatch for " + g.getName());

            if (g.isInitialized()) {
                assertTrue(h.isInitialized(), "Headless block should be initialized for " + g.getName());
                byte[] gBytes = new byte[(int) g.getSize()];
                byte[] hBytes = new byte[(int) h.getSize()];
                g.getBytes(g.getStart(), gBytes);
                h.getBytes(h.getStart(), hBytes);
                assertArrayEquals(gBytes, hBytes, "Block byte contents must match identically for " + g.getName());
            }
        }

        // 2. Symbols equivalence
        List<String> guiSymbols = collectSymbols(gui);
        List<String> headlessSymbols = collectSymbols(headless);
        assertEquals(guiSymbols, headlessSymbols, "Symbols must match symbol-for-symbol identically");

        // 3. External Entry Points
        List<Address> guiEntries = collectEntryPoints(gui);
        List<Address> headlessEntries = collectEntryPoints(headless);
        assertEquals(guiEntries, headlessEntries, "Entry points must match identically");

        // 4. Options categories equivalence
        List<String> optionCategories = List.of(
                RpFirmwareMapper.PROGRAM_OPTIONS_CATEGORY,
                "Embedra RP Board",
                "Embedra Pico SDK",
                "Embedra RP Components",
                "Embedra RP PIO");
        for (String cat : optionCategories) {
            var gOpt = gui.getOptions(cat);
            var hOpt = headless.getOptions(cat);
            List<String> gNames = gOpt.getOptionNames();
            List<String> hNames = hOpt.getOptionNames();
            assertEquals(gNames, hNames, "Option names in category '" + cat + "' must match");
            for (String optName : gNames) {
                assertEquals(gOpt.getObject(optName, null), hOpt.getObject(optName, null),
                        "Option value mismatch for '" + cat + " -> " + optName + "'");
            }
        }

        // 5. Bookmarks equivalence
        List<String> guiBookmarks = collectBookmarks(gui);
        List<String> headlessBookmarks = collectBookmarks(headless);
        assertEquals(guiBookmarks, headlessBookmarks, "Bookmarks must match identically");

        // 6. Comments equivalence across addresses
        AddressSetView initialized = gui.getMemory().getLoadedAndInitializedAddressSet();
        for (Address addr : initialized.getAddresses(true)) {
            String gPlate = gui.getListing().getComment(CommentType.PLATE, addr);
            String hPlate = headless.getListing().getComment(CommentType.PLATE, addr);
            assertEquals(gPlate, hPlate, "Plate comment mismatch at " + addr);

            String gEol = gui.getListing().getComment(CommentType.EOL, addr);
            String hEol = headless.getListing().getComment(CommentType.EOL, addr);
            assertEquals(gEol, hEol, "EOL comment mismatch at " + addr);
        }
    }

    private static List<String> collectSymbols(Program p) {
        List<String> list = new ArrayList<>();
        SymbolIterator it = p.getSymbolTable().getAllSymbols(false);
        while (it.hasNext()) {
            Symbol s = it.next();
            list.add(s.getName() + "@" + s.getAddress());
        }
        list.sort(Comparator.naturalOrder());
        return list;
    }

    private static List<Address> collectEntryPoints(Program p) {
        List<Address> list = new ArrayList<>();
        var it = p.getSymbolTable().getExternalEntryPointIterator();
        while (it.hasNext()) {
            list.add(it.next());
        }
        list.sort(Comparator.naturalOrder());
        return list;
    }

    private static List<String> collectBookmarks(Program p) {
        List<String> list = new ArrayList<>();
        var it = p.getBookmarkManager().getBookmarksIterator();
        while (it.hasNext()) {
            Bookmark b = it.next();
            list.add(b.getCategory() + "|" + b.getTypeString() + "@" + b.getAddress() + ":" + b.getComment());
        }
        list.sort(Comparator.naturalOrder());
        return list;
    }

    private static byte[] fixture(String path) throws IOException {
        try (InputStream input = RpWorkflowEquivalenceTest.class.getResourceAsStream("/fixtures/" + path)) {
            assertNotNull(input, "missing fixture " + path);
            return input.readAllBytes();
        }
    }
}
