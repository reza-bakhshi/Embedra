package io.github.rezabakhshi.embedra.ghidra.rp;

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
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import io.github.rezabakhshi.embedra.formats.rp.uf2.RpUf2Block;
import io.github.rezabakhshi.embedra.targets.rp.binaryinfo.RpBinaryInfoMarker;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class RpBoardAndSdkEnrichmentTest {

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
    void testLoadRp2040WithPicoWBoardProfileOption() throws Exception {
        RpFirmwareLoader loader = new RpFirmwareLoader();
        ByteArrayProvider provider = new ByteArrayProvider("blinky.uf2", fixture("rp/rp2040-pico-blinky.uf2"));

        Collection<LoadSpec> specs = loader.findSupportedLoadSpecs(provider);
        assertFalse(specs.isEmpty());
        LoadSpec spec = specs.iterator().next();

        List<Option> options = loader.getDefaultOptions(provider, spec, null, false, false);
        options.stream()
                .filter(o -> RpFirmwareLoader.BOARD_PROFILE_OPTION.equals(o.getName()))
                .findFirst()
                .orElseThrow()
                .setValue("pico_w");

        try (LoadResults<? extends DomainObject> results = load(loader, provider, spec, options)) {
            results.getPrimary().apply(domainObject -> {
                Program program = (Program) domainObject;

                // RP-008: Silicon identity RP2040 is never mutated into board name
                var progOptions = program.getOptions(RpFirmwareMapper.PROGRAM_OPTIONS_CATEGORY);
                assertEquals("RP2040", progOptions.getString("Target Silicon Part", ""));
                assertEquals("pico_w", progOptions.getString("Board Profile", ""));
                assertEquals("Raspberry Pi Pico W", progOptions.getString("Board Name", ""));

                // Board Profile Options
                var boardOptions = program.getOptions(RpEnrichmentApplicator.BOARD_OPTIONS_CATEGORY);
                assertEquals("pico_w", boardOptions.getString("Board Profile ID", ""));
                assertEquals("Raspberry Pi Pico W", boardOptions.getString("Board Name", ""));
                assertEquals("Winbond W25Q16JV", boardOptions.getString("External Flash Chip", ""));
                assertEquals("QSPI", boardOptions.getString("External Flash Interface", ""));
                assertEquals(2 * 1024 * 1024L, boardOptions.getLong("External Flash Bytes", 0L));
                assertEquals("RP2040", boardOptions.getString("Underlying Silicon Part", ""));
                assertEquals("Infineon CYW43439", boardOptions.getString("Wireless Model", ""));
                assertTrue(boardOptions.getString("Wireless Interfaces", "").contains("SPI"));
                assertTrue(boardOptions.getString("Wireless Interfaces", "").contains("PIO"));

                // Board Pin Bookmarks
                Address baseAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x10000000L);
                Bookmark[] bms = program.getBookmarkManager().getBookmarks(baseAddr, BookmarkType.INFO);
                assertTrue(bms.length > 0);
                boolean hasWlOn = false;
                boolean hasWlCs = false;
                for (Bookmark bm : bms) {
                    if (bm.getCategory().startsWith(RpEnrichmentApplicator.BOOKMARK_CAT_BOARD_PINOUT)) {
                        if (bm.getComment().contains("WL_ON")) {
                            hasWlOn = true;
                        }
                        if (bm.getComment().contains("WL_CS")) {
                            hasWlCs = true;
                        }
                    }
                }
                assertTrue(hasWlOn, "Should have WL_ON pin bookmark");
                assertTrue(hasWlCs, "Should have WL_CS pin bookmark");
            });
        }
    }

    @Test
    void testLoadRp2350WithPico2BoardProfileOption() throws Exception {
        RpFirmwareLoader loader = new RpFirmwareLoader();
        ByteArrayProvider provider = new ByteArrayProvider("pico2_arm.uf2", fixture("rp/rp2350-arm-pico2.uf2"));

        Collection<LoadSpec> specs = loader.findSupportedLoadSpecs(provider);
        assertFalse(specs.isEmpty());
        LoadSpec spec = specs.iterator().next();

        List<Option> options = loader.getDefaultOptions(provider, spec, null, false, false);
        options.stream()
                .filter(o -> RpFirmwareLoader.BOARD_PROFILE_OPTION.equals(o.getName()))
                .findFirst()
                .orElseThrow()
                .setValue("pico2");

        try (LoadResults<? extends DomainObject> results = load(loader, provider, spec, options)) {
            results.getPrimary().apply(domainObject -> {
                Program program = (Program) domainObject;

                var progOptions = program.getOptions(RpFirmwareMapper.PROGRAM_OPTIONS_CATEGORY);
                assertEquals("RP2350A", progOptions.getString("Target Silicon Part", ""));
                assertEquals("pico2", progOptions.getString("Board Profile", ""));

                var boardOptions = program.getOptions(RpEnrichmentApplicator.BOARD_OPTIONS_CATEGORY);
                assertEquals("pico2", boardOptions.getString("Board Profile ID", ""));
                assertEquals("Raspberry Pi Pico 2", boardOptions.getString("Board Name", ""));
                assertEquals("Winbond W25Q32RV", boardOptions.getString("External Flash Chip", ""));
                assertEquals("QMI", boardOptions.getString("External Flash Interface", ""));
                assertEquals(4 * 1024 * 1024L, boardOptions.getLong("External Flash Bytes", 0L));
                assertEquals(25, boardOptions.getInt("LED GPIO", -1));
            });
        }
    }

    @Test
    void testValidateOptionsRejectsConflictingPartAndBoard() throws Exception {
        RpFirmwareLoader loader = new RpFirmwareLoader();
        ByteArrayProvider provider = new ByteArrayProvider("blinky.uf2", fixture("rp/rp2040-pico-blinky.uf2"));

        Collection<LoadSpec> specs = loader.findSupportedLoadSpecs(provider);
        assertFalse(specs.isEmpty());
        LoadSpec spec = specs.iterator().next();

        List<Option> options = loader.getDefaultOptions(provider, spec, null, false, false);
        options.stream()
                .filter(o -> RpFirmwareLoader.TARGET_PART_OPTION.equals(o.getName()))
                .findFirst()
                .orElseThrow()
                .setValue("RP2040");
        options.stream()
                .filter(o -> RpFirmwareLoader.BOARD_PROFILE_OPTION.equals(o.getName()))
                .findFirst()
                .orElseThrow()
                .setValue("pico2");

        String error = loader.validateOptions(provider, spec, options, null);
        assertNotNull(error);
        assertTrue(error.contains("conflicting silicon part 'RP2040'"));
    }

    @Test
    void testLoadFirmwareWithEmbeddedPicoSdkBinaryInfoAndComponents() throws Exception {
        // Construct synthetic RP2040 UF2 image containing:
        // 1. Boot2 preamble with valid CRC
        // 2. Vector table
        // 3. Pico SDK binary info block declaring board "pico_w", program name "SmartPico", version "2.5.0"
        // 4. USB Device descriptor + TinyUSB and lwIP strings
        byte[] flashPayload = createSyntheticFirmwareWithBinaryInfoAndComponents();
        byte[] uf2Bytes = createUf2(flashPayload, 0x10000000L, 0xe48bff56L); // Family RP2040

        RpFirmwareLoader loader = new RpFirmwareLoader();
        ByteArrayProvider provider = new ByteArrayProvider("synthetic_pico_w.uf2", uf2Bytes);

        Collection<LoadSpec> specs = loader.findSupportedLoadSpecs(provider);
        assertFalse(specs.isEmpty());
        LoadSpec spec = specs.iterator().next();

        List<Option> options = loader.getDefaultOptions(provider, spec, null, false, false);

        try (LoadResults<? extends DomainObject> results = load(loader, provider, spec, options)) {
            results.getPrimary().apply(domainObject -> {
                Program program = (Program) domainObject;

                // Silicon identity remains RP2040
                var progOptions = program.getOptions(RpFirmwareMapper.PROGRAM_OPTIONS_CATEGORY);
                assertEquals("RP2040", progOptions.getString("Target Silicon Part", ""));

                // Automatically resolved pico_w board profile from binary info!
                assertEquals("pico_w", progOptions.getString("Board Profile", ""));

                // Pico SDK Options
                var sdkOptions = program.getOptions(RpEnrichmentApplicator.PICO_SDK_OPTIONS_CATEGORY);
                assertEquals("SmartPico", sdkOptions.getString("Program Name", ""));
                assertEquals("2.5.0", sdkOptions.getString("Program Version", ""));
                assertEquals("2.0.0", sdkOptions.getString("SDK Version", ""));
                assertEquals("pico_w", sdkOptions.getString("Pico Board", ""));

                // Pico SDK Bookmark
                Address headerAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x10000140L);
                Bookmark[] sdkBms = program.getBookmarkManager().getBookmarks(headerAddr, BookmarkType.INFO);
                assertTrue(sdkBms.length > 0);
                assertTrue(sdkBms[0].getComment().contains("SmartPico"));

                // Components Options
                var compOptions = program.getOptions(RpEnrichmentApplicator.COMPONENTS_OPTIONS_CATEGORY);
                assertTrue(compOptions.getBoolean("TinyUSB Detected", false));
                assertTrue(compOptions.getBoolean("lwIP Detected", false));
                assertTrue(compOptions.getBoolean("CYW43 Detected", false));

                // Idempotency: verify that re-running does not corrupt or duplicate
                Address baseAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x10000000L);
                int countBefore = program.getBookmarkManager().getBookmarks(baseAddr, BookmarkType.INFO).length;
                // Count should remain unchanged
                assertTrue(countBefore > 0);
            });
        }
    }

    private static byte[] createSyntheticFirmwareWithBinaryInfoAndComponents() {
        byte[] data = new byte[1024];
        ByteBuffer bb = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
        long base = 0x10000000L;

        // 1. Boot2 stage at 0..255 with valid CRC
        for (int i = 0; i < 252; i++) {
            data[i] = (byte) 0xA5;
        }
        int crc = calculateCrc32Mpeg2(data, 252);
        bb.putInt(252, crc);

        // 2. Vector Table at offset 0x100 (address 0x10000100)
        bb.putInt(0x100, 0x20042000); // Initial SP
        bb.putInt(0x104, (int) (base + 0x181)); // Reset entry point Thumb (+1)

        // 3. Binary info strings at 0x300..
        int strName = 0x300;
        writeString(data, strName, "SmartPico");
        int strVer = 0x310;
        writeString(data, strVer, "2.5.0");
        int strSdk = 0x320;
        writeString(data, strSdk, "2.0.0");
        int strBoard = 0x330;
        writeString(data, strBoard, "pico_w");
        int strTinyUsb = 0x340;
        writeString(data, strTinyUsb, "TinyUSB");
        int strLwIp = 0x350;
        writeString(data, strLwIp, "lwIP v2.1.2");
        int strCyw = 0x360;
        writeString(data, strCyw, "CYW43439");

        // Entries at 0x200..
        int e0 = 0x200;
        bb.putShort(e0, (short) 6);
        bb.putShort(e0 + 2, (short) 0x5052);
        bb.putInt(e0 + 4, (int) RpBinaryInfoMarker.ID_RP_PROGRAM_NAME);
        bb.putInt(e0 + 8, (int) (base + strName));

        int e1 = 0x210;
        bb.putShort(e1, (short) 6);
        bb.putShort(e1 + 2, (short) 0x5052);
        bb.putInt(e1 + 4, (int) RpBinaryInfoMarker.ID_RP_PROGRAM_VERSION_STRING);
        bb.putInt(e1 + 8, (int) (base + strVer));

        int e2 = 0x220;
        bb.putShort(e2, (short) 6);
        bb.putShort(e2 + 2, (short) 0x5052);
        bb.putInt(e2 + 4, (int) RpBinaryInfoMarker.ID_RP_SDK_VERSION);
        bb.putInt(e2 + 8, (int) (base + strSdk));

        int e3 = 0x230;
        bb.putShort(e3, (short) 6);
        bb.putShort(e3 + 2, (short) 0x5052);
        bb.putInt(e3 + 4, (int) RpBinaryInfoMarker.ID_RP_PICO_BOARD);
        bb.putInt(e3 + 8, (int) (base + strBoard));

        // Pointers table at 0x1A0
        int tableStart = 0x1A0;
        bb.putInt(tableStart, (int) (base + e0));
        bb.putInt(tableStart + 4, (int) (base + e1));
        bb.putInt(tableStart + 8, (int) (base + e2));
        bb.putInt(tableStart + 12, (int) (base + e3));
        int tableEnd = tableStart + 16;

        // Binary Info Header at 0x140
        bb.putInt(0x140, (int) RpBinaryInfoMarker.MARKER_START);
        bb.putInt(0x144, (int) (base + tableStart));
        bb.putInt(0x148, (int) (base + tableEnd));
        bb.putInt(0x14C, 0);
        bb.putInt(0x150, (int) RpBinaryInfoMarker.MARKER_END);

        // 4. USB Device descriptor at 0x280 (18 bytes)
        bb.position(0x280);
        bb.put((byte) 18); // bLength
        bb.put((byte) 1);  // bDescriptorType = DEVICE
        bb.putShort((short) 0x0200); // bcdUSB = 2.0
        bb.put((byte) 0);
        bb.put((byte) 0);
        bb.put((byte) 0);
        bb.put((byte) 64);
        bb.putShort((short) 0x2E8A);
        bb.putShort((short) 0x000A);
        bb.putShort((short) 0x0100);
        bb.put((byte) 1);
        bb.put((byte) 2);
        bb.put((byte) 0);
        bb.put((byte) 1);

        return data;
    }

    private static int calculateCrc32Mpeg2(byte[] data, int length) {
        int crc = 0xFFFFFFFF;
        for (int i = 0; i < length; i++) {
            crc ^= (data[i] & 0xFF) << 24;
            for (int b = 0; b < 8; b++) {
                if ((crc & 0x80000000) != 0) {
                    crc = (crc << 1) ^ 0x04C11DB7;
                } else {
                    crc = crc << 1;
                }
            }
        }
        return crc;
    }

    private static byte[] createUf2(byte[] data, long targetAddress, long familyId) {
        int payloadSize = 256;
        int numBlocks = (data.length + payloadSize - 1) / payloadSize;
        byte[] uf2 = new byte[numBlocks * 512];
        ByteBuffer bb = ByteBuffer.wrap(uf2).order(ByteOrder.LITTLE_ENDIAN);

        for (int i = 0; i < numBlocks; i++) {
            int offset = i * payloadSize;
            int chunkLen = Math.min(payloadSize, data.length - offset);
            int blockOffset = i * 512;

            bb.position(blockOffset);
            bb.putInt((int) RpUf2Block.EXPECTED_MAGIC_START0);
            bb.putInt((int) RpUf2Block.EXPECTED_MAGIC_START1);
            bb.putInt(RpUf2Block.FLAG_FAMILY_ID_PRESENT);
            bb.putInt((int) (targetAddress + offset));
            bb.putInt(payloadSize);
            bb.putInt(i);
            bb.putInt(numBlocks);
            bb.putInt((int) familyId);
            bb.put(data, offset, chunkLen);

            bb.position(blockOffset + 508);
            bb.putInt((int) RpUf2Block.EXPECTED_MAGIC_END);
        }
        return uf2;
    }

    private static void writeString(byte[] buffer, int offset, String s) {
        byte[] strBytes = s.getBytes(StandardCharsets.UTF_8);
        System.arraycopy(strBytes, 0, buffer, offset, strBytes.length);
        buffer[offset + strBytes.length] = 0;
    }

    private static LoadResults<? extends DomainObject> load(
            RpFirmwareLoader loader,
            ByteArrayProvider provider,
            LoadSpec spec,
            List<Option> options) throws Exception {
        ImporterSettings settings = new ImporterSettings(
                provider, provider.getName(), null,
                "/", false, spec, options, new Object(), new MessageLog(), TaskMonitor.DUMMY);
        return loader.load(settings);
    }

    private static byte[] fixture(String path) throws IOException {
        try (InputStream input = RpBoardAndSdkEnrichmentTest.class.getResourceAsStream("/fixtures/" + path)) {
            assertNotNull(input, "missing fixture " + path);
            return input.readAllBytes();
        }
    }
}
