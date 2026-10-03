package io.github.rezabakhshi.embedra.targets.rp;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.formats.rp.uf2.RpUf2Family;
import io.github.rezabakhshi.embedra.formats.rp.uf2.RpUf2Image;
import io.github.rezabakhshi.embedra.formats.rp.uf2.RpUf2Parser;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.targets.rp.catalog.RpBoardProfile;
import io.github.rezabakhshi.embedra.targets.rp.catalog.RpDeviceCatalog;
import io.github.rezabakhshi.embedra.targets.rp.catalog.RpDeviceCatalogLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class RpFixtureTest {

    private static final Path FIXTURES_DIR = Path.of("src/test/resources/fixtures/rp");

    private static RpDeviceCatalog catalog;

    private static RpTargetResolver resolver;

    @BeforeAll
    static void setUp() throws Exception {
        catalog = RpDeviceCatalogLoader.loadDefault();
        resolver = new RpTargetResolver(catalog);
    }

    @Test
    void testRp2040ElfAndBinFixture() throws Exception {
        Path elfPath = FIXTURES_DIR.resolve("rp2040-freestanding-dualcore.elf");
        assertTrue(Files.exists(elfPath), "ELF fixture exists");
        byte[] elfBytes = Files.readAllBytes(elfPath);
        assertTrue(elfBytes.length > 0);

        Path boot2BinPath = FIXTURES_DIR.resolve("rp2040-boot2-xip.bin");
        assertTrue(Files.exists(boot2BinPath), "Boot2 BIN fixture exists");
        assertEquals(256, Files.size(boot2BinPath), "Boot2 must be 256 bytes");

        RpTargetProvider provider = resolver.resolvePart("RP2040").orElseThrow();
        Optional<RpBoardProfile> pico = catalog.findBoardProfile("pico");
        assertTrue(pico.isPresent());

        // Target address is mapped in Flash XIP
        assertTrue(provider.isAddressMapped(0x10000000L, pico.get()));
        assertTrue(provider.isAddressMapped(0x10000100L, pico.get()));

        // Entry point 0x10000000 (Thumb mode 0x10000001) is valid
        assertTrue(provider.isValidEntryPoint(0x10000001L, Rp2040TargetProvider.ARCH_ARM, pico.get()));
    }

    @Test
    void testRp2350ArmElfFixture() throws Exception {
        Path elfPath = FIXTURES_DIR.resolve("rp2350-arm-trustzone.elf");
        assertTrue(Files.exists(elfPath), "RP2350 ARM ELF fixture exists");

        RpTargetProvider provider = resolver.resolvePart("RP2350A").orElseThrow();
        Optional<RpBoardProfile> pico2 = catalog.findBoardProfile("pico2");
        assertTrue(pico2.isPresent());

        // Target address is mapped in Flash XIP
        assertTrue(provider.isAddressMapped(0x10000000L, pico2.get()));

        // Reset Handler at 0x10000141 (Thumb mode) is valid
        assertTrue(provider.isValidEntryPoint(0x10000141L, Rp2350TargetProvider.ARCH_ARM, pico2.get()));
    }

    @Test
    void testRp2350RiscvElfFixture() throws Exception {
        Path elfPath = FIXTURES_DIR.resolve("rp2350-riscv-trap.elf");
        assertTrue(Files.exists(elfPath), "RP2350 RISC-V ELF fixture exists");

        RpTargetProvider provider = resolver.resolvePart("RP2350B").orElseThrow();
        Optional<RpBoardProfile> pico2 = catalog.findBoardProfile("pico2");
        assertTrue(pico2.isPresent());

        // Entry at 0x10000100 is valid
        assertTrue(provider.isValidEntryPoint(0x10000100L, Rp2350TargetProvider.ARCH_RISCV, pico2.get()));
    }

    @Test
    void testRp2354StackedFlashBinFixture() throws Exception {
        Path binPath = FIXTURES_DIR.resolve("rp2354-stacked-flash.bin");
        assertTrue(Files.exists(binPath), "RP2354 stacked flash fixture exists");

        RpTargetProvider provider = resolver.resolvePart("RP2354A").orElseThrow();
        assertTrue(provider.siliconRecord().hasInternalFlash());

        // Stacked flash base address is mapped
        assertTrue(provider.isAddressMapped(0x10000000L, null));
    }

    @Test
    void testUf2ConversionExtractionRoundTrip() throws Exception {
        Path uf2Path = FIXTURES_DIR.resolve("rp2040-pico-blinky.uf2");
        RpUf2Image image = RpUf2Parser.parse(uf2Path, ParserLimits.defaults(), CancellationToken.none());

        assertEquals(RpUf2Family.RP2040, image.family());
        byte[] flat = image.extractContinuousBinary();
        assertTrue(flat.length >= 256);

        // Check boot2 magic/header in the extracted continuous binary
        Path boot2Path = FIXTURES_DIR.resolve("rp2040-boot2-xip.bin");
        byte[] boot2Expected = Files.readAllBytes(boot2Path);

        byte[] extractedBoot2 = new byte[256];
        System.arraycopy(flat, 0, extractedBoot2, 0, 256);
        assertArrayEquals(boot2Expected, extractedBoot2);
    }
}
