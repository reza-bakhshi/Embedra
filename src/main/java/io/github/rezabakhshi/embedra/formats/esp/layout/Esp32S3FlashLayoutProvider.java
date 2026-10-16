package io.github.rezabakhshi.embedra.formats.esp.layout;

import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.core.io.SourceRange;
import io.github.rezabakhshi.embedra.formats.esp.EspImage;
import io.github.rezabakhshi.embedra.targets.esp.catalog.EspCpuIsa;
import java.util.Objects;
import java.util.Optional;

/**
 * Concrete flash layout provider for ESP32-S3.
 */
public final class Esp32S3FlashLayoutProvider implements EspFlashLayoutProvider {
    public static final int ESP32_S3_CHIP_ID = 9;

    public static final Esp32S3FlashLayoutProvider INSTANCE = new Esp32S3FlashLayoutProvider();

    private static final EspFlashLayoutProfile PROFILE = new EspFlashLayoutProfile(
            "ESP32-S3",
            ESP32_S3_CHIP_ID,
            "ESP32-S3",
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
            "esptool/targets/esp32s3.py + ESP-IDF components/soc/esp32s3"
    );

    @Override
    public String providerId() {
        return "esp32s3";
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
        if (image.header().chipId() != ESP32_S3_CHIP_ID) {
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.ESP_CHIP_MISMATCH,
                    "ESP image chip ID " + image.header().chipId() + " does not match ESP32-S3 (chip ID 9) for " + role,
                    new SourceRange(12, 2)
            ));
        }
    }
}
