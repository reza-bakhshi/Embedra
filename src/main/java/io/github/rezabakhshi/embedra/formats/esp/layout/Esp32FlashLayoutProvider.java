package io.github.rezabakhshi.embedra.formats.esp.layout;

import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.core.io.SourceRange;
import io.github.rezabakhshi.embedra.formats.esp.EspImage;
import io.github.rezabakhshi.embedra.targets.esp.catalog.EspCpuIsa;
import java.util.Objects;

/**
 * Concrete flash layout provider for original ESP32.
 * Bootloader starts at 0x1000 (4 KiB); partition table at 0x8000.
 */
public final class Esp32FlashLayoutProvider implements EspFlashLayoutProvider {
    public static final int ESP32_CHIP_ID = 0;

    public static final Esp32FlashLayoutProvider INSTANCE = new Esp32FlashLayoutProvider();

    private static final EspFlashLayoutProfile PROFILE = new EspFlashLayoutProfile(
            "ESP32",
            ESP32_CHIP_ID,
            "ESP32",
            EspCpuIsa.XTENSA,
            "Xtensa:LE:32:default",
            "default",
            0x1000,
            0x1000,
            0x7000,
            0x8000,
            0x8000,
            0x10000,
            0x10000,
            16 * 1024 * 1024,
            "esptool/targets/esp32.py + ESP-IDF components/soc/esp32"
    );

    @Override
    public String providerId() {
        return "esp32";
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
        if (image.header().chipId() != ESP32_CHIP_ID) {
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.ESP_CHIP_MISMATCH,
                    "ESP image chip ID " + image.header().chipId() + " does not match ESP32 (chip ID 0) for " + role,
                    new SourceRange(12, 2)
            ));
        }
    }
}
