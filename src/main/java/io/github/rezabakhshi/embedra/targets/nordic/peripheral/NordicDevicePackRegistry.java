package io.github.rezabakhshi.embedra.targets.nordic.peripheral;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.targets.nordic.catalog.NordicPartRecord;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Authoritative registry of Nordic peripheral definition packs for nRF51, nRF52, nRF53, nRF54, and nRF91 series.
 */
public final class NordicDevicePackRegistry {

    public static final Path DEFAULT_PACKS_DIR = Path.of("catalogs/nordic/packs");

    private final Map<String, NordicPeripheralPack> packsBySeries;

    public NordicDevicePackRegistry(List<NordicPeripheralPack> packs) {
        Objects.requireNonNull(packs, "packs must not be null");
        Map<String, NordicPeripheralPack> map = new HashMap<>();
        for (NordicPeripheralPack pack : packs) {
            map.put(pack.series().toUpperCase(Locale.ROOT), pack);
        }
        this.packsBySeries = Collections.unmodifiableMap(map);
    }

    public static NordicDevicePackRegistry loadDefault() throws DiagnosticException {
        if (Files.isDirectory(DEFAULT_PACKS_DIR)) {
            return load(DEFAULT_PACKS_DIR, ParserLimits.defaults(), CancellationToken.none());
        }
        return createDefaultBuiltin();
    }

    public static NordicDevicePackRegistry createDefaultBuiltin() {
        return new NordicDevicePackRegistry(List.of(
            NordicDefaultPacks.createNrf51Pack(),
            NordicDefaultPacks.createNrf52Pack(),
            NordicDefaultPacks.createNrf53Pack(),
            NordicDefaultPacks.createNrf54Pack(),
            NordicDefaultPacks.createNrf91Pack()
        ));
    }

    public static NordicDevicePackRegistry load(
            Path packsDir, ParserLimits limits, CancellationToken token)
            throws DiagnosticException {
        Objects.requireNonNull(packsDir, "packsDir must not be null");
        Objects.requireNonNull(limits, "limits must not be null");
        Objects.requireNonNull(token, "token must not be null");

        token.throwIfCancellationRequested();

        if (!Files.isDirectory(packsDir)) {
            throw new DiagnosticException(Diagnostic.error(
                DiagnosticCode.NORDIC_PACK_INVALID,
                "Nordic peripheral packs directory not found: " + packsDir,
                null));
        }

        String[] seriesKeys = {"nrf51", "nrf52", "nrf53", "nrf54", "nrf91"};
        Map<String, NordicPeripheralPack> loaded = new HashMap<>();

        for (String s : seriesKeys) {
            Path jsonPath = packsDir.resolve(s + "-peripherals.json");
            Path shaPath = packsDir.resolve(s + "-peripherals.sha256");

            if (Files.isRegularFile(jsonPath)) {
                NordicPeripheralPack pack = NordicPeripheralPackLoader.load(jsonPath, shaPath, limits, token);
                loaded.put(pack.series().toUpperCase(Locale.ROOT), pack);
            }
        }

        if (loaded.isEmpty()) {
            return createDefaultBuiltin();
        }

        return new NordicDevicePackRegistry(List.copyOf(loaded.values()));
    }

    public Optional<NordicPeripheralPack> packForSeries(String series) {
        if (series == null || series.isBlank()) {
            return Optional.empty();
        }
        String s = series.trim().toUpperCase(Locale.ROOT);
        return Optional.ofNullable(packsBySeries.get(s));
    }

    public Optional<NordicPeripheralPack> packForPart(NordicPartRecord part) {
        if (part == null) {
            return Optional.empty();
        }
        return packForSeries(part.series());
    }

    public NordicPeripheralPack getRequiredPack(String series) throws DiagnosticException {
        return packForSeries(series).orElseThrow(() -> new DiagnosticException(Diagnostic.error(
            DiagnosticCode.NORDIC_PACK_INVALID,
            "No peripheral pack available for series: " + series,
            null)));
    }

    public NordicPeripheralPack getRequiredPack(NordicPartRecord part) throws DiagnosticException {
        Objects.requireNonNull(part, "part must not be null");
        return packForPart(part).orElseThrow(() -> new DiagnosticException(Diagnostic.error(
            DiagnosticCode.NORDIC_PACK_INVALID,
            "No peripheral pack available for part: " + part.exactPart(),
            null)));
    }

    public int packCount() {
        return packsBySeries.size();
    }
}
