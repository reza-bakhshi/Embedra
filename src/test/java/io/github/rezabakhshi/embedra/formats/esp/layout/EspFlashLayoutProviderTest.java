package io.github.rezabakhshi.embedra.formats.esp.layout;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.formats.esp.EspImage;
import io.github.rezabakhshi.embedra.formats.esp.EspImageFooter;
import io.github.rezabakhshi.embedra.formats.esp.EspImageHeader;
import io.github.rezabakhshi.embedra.formats.esp.EspImageParser;
import io.github.rezabakhshi.embedra.targets.esp.catalog.EspCpuIsa;
import java.util.List;
import org.junit.jupiter.api.Test;

class EspFlashLayoutProviderTest {
    @Test
    void profileEnforcesInvariantsAndBounds() {
        EspFlashLayoutProfile profile = Esp32S3FlashLayoutProvider.INSTANCE.profile();
        assertEquals("ESP32-S3", profile.series());
        assertEquals(9, profile.chipId());
        assertEquals(EspCpuIsa.XTENSA, profile.isa());
        assertEquals("Xtensa:LE:32:default", profile.defaultLanguageId());
        assertEquals(0x0000, profile.bootloaderOffset());
        assertEquals(0x8000, profile.defaultPartitionTableOffset());
        assertEquals(0x8000, profile.minPartitionTableOffset());
        assertEquals(0x10000, profile.maxPartitionTableOffset());
        assertEquals(0x10000, profile.mmuPageSize());

        assertThrows(IllegalArgumentException.class, () -> new EspFlashLayoutProfile(
                "INVALID", 99, "Invalid", EspCpuIsa.XTENSA, "Xtensa:LE:32:default", "default",
                0x8000, 0x1000, 0x8000, 0x1000, 0x1000, 0x8000, 0x10000, 16 * 1024 * 1024, "test"
        ));
    }

    @Test
    void providerValidatesTargetOffsetsAndImageChipId() throws Exception {
        EspFlashLayoutProvider provider = Esp32S3FlashLayoutProvider.INSTANCE;
        assertTrue(provider.matchesChipId(9));
        assertFalse(provider.matchesChipId(0));
        assertTrue(provider.isValidBootloaderOffset(0));
        assertFalse(provider.isValidBootloaderOffset(0x1000));
        assertTrue(provider.isValidPartitionTableOffset(0x8000));
        assertTrue(provider.isValidPartitionTableOffset(0x9000));
        assertTrue(provider.isValidPartitionTableOffset(0x10000));
        assertFalse(provider.isValidPartitionTableOffset(0x7000));
        assertFalse(provider.isValidPartitionTableOffset(0x8001));

        EspImage s3Image = EspImageParser.parse(
                readFixture("/fixtures/esp32s3/esp32s3-freestanding-minimal.bin"),
                io.github.rezabakhshi.embedra.core.ParserLimits.defaults(),
                io.github.rezabakhshi.embedra.core.CancellationToken.none()
        );
        provider.validateBootloader(s3Image);
        provider.validateApplication(s3Image);

        EspImage wrongChipImage = EspImageParser.parse(
                readFixture("/fixtures/esp32/esp32-freestanding-minimal.bin"),
                io.github.rezabakhshi.embedra.core.ParserLimits.defaults(),
                io.github.rezabakhshi.embedra.core.CancellationToken.none()
        );
        DiagnosticException failure = assertThrows(DiagnosticException.class,
                () -> provider.validateBootloader(wrongChipImage));
        assertEquals(DiagnosticCode.ESP_CHIP_MISMATCH, failure.diagnostic().code());
    }

    @Test
    void registryResolvesDefaultAndCustomProviders() {
        EspFlashLayoutRegistry registry = EspFlashLayoutRegistry.defaults();
        assertNotNull(registry.requireByChipId(9));
        assertEquals("esp32s3", registry.requireByChipId(9).providerId());
        assertTrue(registry.findBySeries("ESP32-S3").isPresent());
        assertTrue(registry.findBySeries("esp32s3").isPresent());
        assertFalse(registry.findBySeries("nonexistent").isPresent());
        assertThrows(IllegalArgumentException.class, () -> registry.requireByChipId(9999));
    }

    private static byte[] readFixture(String path) {
        try (var in = EspFlashLayoutProviderTest.class.getResourceAsStream(path)) {
            assertNotNull(in, "missing fixture " + path);
            return in.readAllBytes();
        }
        catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
