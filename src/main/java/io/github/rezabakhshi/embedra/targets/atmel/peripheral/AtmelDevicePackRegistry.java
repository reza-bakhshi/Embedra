package io.github.rezabakhshi.embedra.targets.atmel.peripheral;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.TreeMap;

/**
 * Authoritative in-memory registry of Atmel/Microchip peripheral register data packs.
 */
public final class AtmelDevicePackRegistry {

    public static final Path DEFAULT_PACKS_DIR = Path.of("catalogs/atmel/packs");

    private final Map<String, AtmelPeripheralPack> packsByPart;

    private final Map<String, AtmelPeripheralPack> packsByDevice;

    private final List<AtmelPeripheralPack> allPacksList;

    public AtmelDevicePackRegistry(List<AtmelPeripheralPack> packs) {
        Objects.requireNonNull(packs, "packs must not be null");
        Map<String, AtmelPeripheralPack> byPart = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        Map<String, AtmelPeripheralPack> byDevice = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        for (AtmelPeripheralPack pack : packs) {
            byPart.put(pack.catalogPart(), pack);
            byDevice.put(pack.device(), pack);
        }
        this.packsByPart = Collections.unmodifiableMap(byPart);
        this.packsByDevice = Collections.unmodifiableMap(byDevice);
        this.allPacksList = List.copyOf(packs);
    }

    public static AtmelDevicePackRegistry loadDefault() throws DiagnosticException {
        return load(DEFAULT_PACKS_DIR, ParserLimits.defaults(), CancellationToken.none());
    }

    public static AtmelDevicePackRegistry load(
            Path packsDir, ParserLimits limits, CancellationToken token)
            throws DiagnosticException {
        Objects.requireNonNull(packsDir, "packsDir must not be null");
        Objects.requireNonNull(limits, "limits must not be null");
        Objects.requireNonNull(token, "token must not be null");

        token.throwIfCancellationRequested();

        if (!Files.isDirectory(packsDir)) {
            throw new DiagnosticException(Diagnostic.error(
                DiagnosticCode.ATMEL_PACK_INVALID,
                "Atmel peripheral packs directory not found: " + packsDir,
                null));
        }

        Map<String, AtmelPeripheralPack> loaded = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(packsDir, "*-peripherals.json")) {
            for (Path jsonPath : stream) {
                token.throwIfCancellationRequested();
                String fileName = jsonPath.getFileName().toString();
                String basePrefix = fileName.substring(0, fileName.length() - "-peripherals.json".length());
                Path shaPath = packsDir.resolve(basePrefix + "-peripherals.sha256");

                AtmelPeripheralPack pack = AtmelPeripheralPackLoader.load(jsonPath, shaPath, limits, token);
                loaded.put(pack.catalogPart(), pack);
            }
        } catch (IOException e) {
            throw new DiagnosticException(Diagnostic.error(
                DiagnosticCode.ATMEL_PACK_INVALID,
                "Failed to scan Atmel peripheral packs directory: " + e.getMessage(),
                null));
        }

        return new AtmelDevicePackRegistry(List.copyOf(loaded.values()));
    }

    public Optional<AtmelPeripheralPack> packForPart(String partName) {
        if (partName == null || partName.isBlank()) {
            return Optional.empty();
        }
        return Optional.ofNullable(packsByPart.get(partName.trim()));
    }

    public Optional<AtmelPeripheralPack> packForDevice(String deviceName) {
        if (deviceName == null || deviceName.isBlank()) {
            return Optional.empty();
        }
        AtmelPeripheralPack pack = packsByDevice.get(deviceName.trim());
        if (pack != null) {
            return Optional.of(pack);
        }
        return Optional.ofNullable(packsByPart.get(deviceName.trim()));
    }

    public boolean hasPackForPart(String partName) {
        return packForPart(partName).isPresent();
    }

    public List<AtmelPeripheralPack> allPacks() {
        return allPacksList;
    }

    public int packCount() {
        return allPacksList.size();
    }
}
