package io.github.rezabakhshi.embedra.formats.esp.layout;

import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.core.io.SourceRange;
import io.github.rezabakhshi.embedra.formats.esp.EspImage;
import io.github.rezabakhshi.embedra.targets.esp.catalog.EspCpuIsa;
import java.util.Objects;

/**
 * Concrete flash layout provider for ESP32-S2.
 * Bootloader starts at 0x0000; partition table at 0x8000.
 */
public final class Esp32S2FlashLayoutProvider implements EspFlashLayoutProvider {
    public static final int ESP32_S2_CHIP_ID = 2;

    public static final Esp32S2FlashLayoutProvider INSTANCE = new Esp32S2FlashLayoutProvider();

    private static final EspFlashLayoutProfile PROFILE = new EspFlashLayoutProfile(
            "ESP32-S2",
            ESP32_S2_CHIP_ID,
            "ESP32-S2",
            EspCpuIsa.XTENSA,
            "Xtensa:LE:32:default",
            "default",
            0x0000,
            0x1000,
            0x8000,
            0x8000,
            0x8000,
            0x10000,
            0x10000,
            16 * 1024 * 1024,
            "esptool/targets/esp32s2.py + ESP-IDF components/soc/esp32s2"
    );

    @Override
    public String providerId() {
        return "esp32s2";
    }

    @Override
    public EspFlashLayoutProfile profile() {
        return PROFILE;
    }

    @Override
    public void validateBootloader(EspImage bootloader) throws DiagnosticException {
        Objects.requireNonNull(bootloader, "bootloader");
        validateImage(bootloader, "bootloader");
    }

    @Override
    public void validateApplication(EspImage application) throws DiagnosticException {
        Objects.requireNonNull(application, "application");
        validateImage(application, "application");
    }

    private void validateImage(EspImage image, String role) throws DiagnosticException {
        if (image.header().chipId() != ESP32_S2_CHIP_ID) {
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.ESP_CHIP_MISMATCH,
                    "ESP image chip ID " + image.header().chipId() + " does not match ESP32-S2 (chip ID 2) for " + role,
                    new SourceRange(12, 2)
            ));
        }
    }
}
