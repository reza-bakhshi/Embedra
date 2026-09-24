package io.github.rezabakhshi.embedra.pack;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.nio.file.Path;
import java.util.Objects;

/** Integrity-first enrichment-pack loader bound to an exact ESP target. */
public final class EspTargetPackLoader {
    private EspTargetPackLoader() {
    }

    public static EspRomSymbolPack loadRom(Path directory, String deviceId,
            ParserLimits limits, CancellationToken cancellation) throws DiagnosticException {
        validateDeviceId(deviceId);
        return Esp32S3PackLoader.loadRom(directory, deviceId, limits, cancellation);
    }

    public static EspPeripheralPack loadPeripherals(Path directory, String deviceId,
            ParserLimits limits, CancellationToken cancellation) throws DiagnosticException {
        validateDeviceId(deviceId);
        return Esp32S3PackLoader.loadPeripherals(directory, deviceId, limits, cancellation);
    }

    public static EspSvdPack loadSvd(Path directory, String deviceId, ParserLimits limits,
            CancellationToken cancellation) throws DiagnosticException {
        validateDeviceId(deviceId);
        return EspSvdPackLoader.load(directory, deviceId, limits, cancellation);
    }

    private static void validateDeviceId(String deviceId) {
        Objects.requireNonNull(deviceId, "deviceId");
        if (!deviceId.matches("[a-z0-9]+")) {
            throw new IllegalArgumentException("ESP pack device ID is invalid");
        }
    }
}
