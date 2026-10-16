package io.github.rezabakhshi.embedra.formats.esp.layout;

import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.core.io.SourceRange;
import io.github.rezabakhshi.embedra.formats.esp.EspImage;
import io.github.rezabakhshi.embedra.targets.esp.catalog.EspCpuIsa;
import java.util.Objects;

/**
 * Concrete flash layout provider for an ESP32 RISC-V series.
 * Bootloader starts at 0x0000; default partition table at 0x8000; language RISCV:LE:32:default.
 */
public final class EspRiscVFlashLayoutProvider implements EspFlashLayoutProvider {
    private final String providerId;

    private final EspFlashLayoutProfile profile;

    public EspRiscVFlashLayoutProvider(String series, int chipId, String displayName,
            long minBootloaderLength, long maxBootloaderLength, long defaultPartitionTableOffset,
            long minPartitionTableOffset, long maxPartitionTableOffset, int mmuPageSize,
            long maxSupportedFlashSize, String referenceSource) {
        Objects.requireNonNull(series, "series");
        this.providerId = series.toLowerCase().replace("-", "");
        this.profile = new EspFlashLayoutProfile(
                series,
                chipId,
                displayName,
                EspCpuIsa.RISCV,
                "RISCV:LE:32:default",
                "gcc",
                0x0000,
                minBootloaderLength,
                maxBootloaderLength,
                defaultPartitionTableOffset,
                minPartitionTableOffset,
                maxPartitionTableOffset,
                mmuPageSize,
                maxSupportedFlashSize,
                referenceSource
        );
    }

    public static EspRiscVFlashLayoutProvider of(String series, int chipId, String displayName,
            String referenceSource) {
        return new EspRiscVFlashLayoutProvider(
                series,
                chipId,
                displayName,
                0x1000,
                0x8000,
                0x8000,
                0x8000,
                0x10000,
                0x10000,
                16 * 1024 * 1024,
                referenceSource
        );
    }

    @Override
    public String providerId() {
        return providerId;
    }

    @Override
    public EspFlashLayoutProfile profile() {
        return profile;
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
        if (image.header().chipId() != chipId()) {
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.ESP_CHIP_MISMATCH,
                    "ESP image chip ID " + image.header().chipId() + " does not match "
                            + profile.series() + " (chip ID " + chipId() + ") for " + role,
                    new SourceRange(12, 2)
            ));
        }
    }
}
