package io.github.rezabakhshi.embedra.ghidra.rp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
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
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.task.TaskMonitor;
import io.github.rezabakhshi.embedra.ghidra.rp.pio.RpPioApplicator;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.Collection;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class RpPioIntegrationTest {

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
    }

    @Test
    void testRp2040PioDiscoveryAndApertures() throws Exception {
        byte[] input = fixture("rp/rp2040-pico-blinky.uf2");
        RpFirmwareLoader loader = new RpFirmwareLoader();
        ByteArrayProvider provider = new ByteArrayProvider("blinky.uf2", input);
        Collection<LoadSpec> specs = loader.findSupportedLoadSpecs(provider);
        LoadSpec spec = specs.iterator().next();
        List<Option> options = loader.getDefaultOptions(provider, spec, null, false, false);

        ImporterSettings settings = new ImporterSettings(
                provider, provider.getName(), null,
                "/", false, spec, options, CONSUMER, new MessageLog(), TaskMonitor.DUMMY);

        try (LoadResults<? extends DomainObject> results = loader.load(settings)) {
            final Program[] progRef = new Program[1];
            results.getPrimary().apply(d -> progRef[0] = (Program) d);
            Program program = progRef[0];

            // 1. Verify PIO program options
            var pioOptions = program.getOptions(RpPioApplicator.PROGRAM_OPTIONS_CATEGORY);
            assertEquals(2, pioOptions.getInt("PIO Blocks Available", 0));
            assertEquals(8, pioOptions.getInt("State Machines Available", 0));
            int discovered = pioOptions.getInt("Discovered Programs Count", -1);
            assertTrue(discovered >= 1, "Should discover at least 1 PIO program in RP2040 firmware");

            // 2. Verify PIO hardware apertures (PIO0 at 0x50200000, PIO1 at 0x50300000)
            Address pio0Base = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x50200000L);
            Address pio1Base = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x50300000L);

            MemoryBlock pio0Block = program.getMemory().getBlock(pio0Base);
            assertNotNull(pio0Block, "PIO0 aperture memory block should exist");
            assertEquals("pio0", pio0Block.getName());
            assertTrue(pio0Block.isVolatile());
            assertTrue(pio0Block.isRead());
            assertTrue(pio0Block.isWrite());
            assertFalse(pio0Block.isExecute());

            MemoryBlock pio1Block = program.getMemory().getBlock(pio1Base);
            assertNotNull(pio1Block, "PIO1 aperture memory block should exist");
            assertEquals("pio1", pio1Block.getName());

            // 3. Verify PIO Aperture bookmarks
            Bookmark[] pio0Bms = program.getBookmarkManager().getBookmarks(pio0Base);
            assertTrue(pio0Bms.length > 0);
            assertEquals(RpPioApplicator.BOOKMARK_CATEGORY_APERTURE, pio0Bms[0].getCategory());
            assertTrue(pio0Bms[0].getComment().contains("4 State Machines"));

            // 4. Verify discovered PIO program annotations at rp_pio_instructions (0x10000190):
            Address progAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x10000190L);
            Bookmark[] pioBms = program.getBookmarkManager().getBookmarks(progAddr);
            assertTrue(pioBms.length > 0, "Should have bookmark at PIO program address 0x10000190");
            assertEquals(RpPioApplicator.BOOKMARK_CATEGORY_PROGRAM, pioBms[0].getCategory());

            // Plate comment exists on program start
            String plate = program.getListing().getComment(CommentType.PLATE, progAddr);
            assertNotNull(plate);
            assertTrue(plate.contains("=== Embedra Disassembled PIO Program ==="));
            assertTrue(plate.contains("set pins, 1"));

            // EOL comment exists with [PIO] prefix
            String eol = program.getListing().getComment(CommentType.EOL, progAddr);
            assertNotNull(eol);
            assertTrue(eol.startsWith("[PIO]"));

            // Ensure instruction was NOT disassembled as ARM Thumb
            Instruction cpuInstr = program.getListing().getInstructionAt(progAddr);
            assertEquals(null, cpuInstr, "PIO word must not be disassembled as ARM Thumb instruction");
        }
    }

    @Test
    void testRp2350ThreePioApertures() throws Exception {
        byte[] input = fixture("rp/rp2350-arm-pico2.uf2");
        RpFirmwareLoader loader = new RpFirmwareLoader();
        ByteArrayProvider provider = new ByteArrayProvider("pico2.uf2", input);
        Collection<LoadSpec> specs = loader.findSupportedLoadSpecs(provider);
        LoadSpec spec = specs.iterator().next();
        List<Option> options = loader.getDefaultOptions(provider, spec, null, false, false);

        ImporterSettings settings = new ImporterSettings(
                provider, provider.getName(), null,
                "/", false, spec, options, CONSUMER, new MessageLog(), TaskMonitor.DUMMY);

        try (LoadResults<? extends DomainObject> results = loader.load(settings)) {
            final Program[] progRef = new Program[1];
            results.getPrimary().apply(d -> progRef[0] = (Program) d);
            Program program = progRef[0];

            // 1. Verify 3 PIO blocks (12 state machines) on RP2350
            var pioOptions = program.getOptions(RpPioApplicator.PROGRAM_OPTIONS_CATEGORY);
            assertEquals(3, pioOptions.getInt("PIO Blocks Available", 0));
            assertEquals(12, pioOptions.getInt("State Machines Available", 0));

            // 2. Verify all 3 PIO apertures exist: PIO0 (0x50200000), PIO1 (0x50300000), PIO2 (0x50400000)
            Address pio0Base = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x50200000L);
            Address pio1Base = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x50300000L);
            Address pio2Base = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x50400000L);

            assertNotNull(program.getMemory().getBlock(pio0Base), "PIO0 block should exist");
            assertNotNull(program.getMemory().getBlock(pio1Base), "PIO1 block should exist");
            assertNotNull(program.getMemory().getBlock(pio2Base), "PIO2 block should exist");

            assertEquals("pio0", program.getMemory().getBlock(pio0Base).getName());
            assertEquals("pio1", program.getMemory().getBlock(pio1Base).getName());
            assertEquals("pio2", program.getMemory().getBlock(pio2Base).getName());

            // PIO2 aperture bookmark
            Bookmark[] pio2Bms = program.getBookmarkManager().getBookmarks(pio2Base);
            assertTrue(pio2Bms.length > 0);
            assertEquals(RpPioApplicator.BOOKMARK_CATEGORY_APERTURE, pio2Bms[0].getCategory());
            assertTrue(pio2Bms[0].getComment().contains("PIO Block 2"));
        }
    }

    private static byte[] fixture(String path) throws IOException {
        try (InputStream input = RpPioIntegrationTest.class.getResourceAsStream("/fixtures/" + path)) {
            assertNotNull(input, "missing fixture " + path);
            return input.readAllBytes();
        }
    }
}
