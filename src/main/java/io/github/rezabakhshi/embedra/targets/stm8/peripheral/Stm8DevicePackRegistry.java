package io.github.rezabakhshi.embedra.targets.stm8.peripheral;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.targets.stm8.catalog.Stm8PartRecord;
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
 * Authoritative registry of STM8 peripheral definition packs for STM8S, STM8L, and STM8A families.
 */
public final class Stm8DevicePackRegistry {

    public static final Path DEFAULT_PACKS_DIR = Path.of("catalogs/stm8/packs");

    private final Map<String, Stm8PeripheralPack> packsByFamily;

    public Stm8DevicePackRegistry(List<Stm8PeripheralPack> packs) {
        Objects.requireNonNull(packs, "packs must not be null");
        Map<String, Stm8PeripheralPack> map = new HashMap<>();
        for (Stm8PeripheralPack pack : packs) {
            map.put(pack.family().toUpperCase(Locale.ROOT), pack);
        }
        this.packsByFamily = Collections.unmodifiableMap(map);
    }

    public static Stm8DevicePackRegistry loadDefault() throws DiagnosticException {
        return load(DEFAULT_PACKS_DIR, ParserLimits.defaults(), CancellationToken.none());
    }

    public static Stm8DevicePackRegistry load(
            Path packsDir, ParserLimits limits, CancellationToken token)
            throws DiagnosticException {
        Objects.requireNonNull(packsDir, "packsDir must not be null");
        Objects.requireNonNull(limits, "limits must not be null");
        Objects.requireNonNull(token, "token must not be null");

        token.throwIfCancellationRequested();

        if (!Files.isDirectory(packsDir)) {
            throw new DiagnosticException(Diagnostic.error(
                DiagnosticCode.STM8_PACK_INVALID,
                "STM8 peripheral packs directory not found: " + packsDir,
                null));
        }

        String[] families = {"stm8s", "stm8l", "stm8a"};
        Map<String, Stm8PeripheralPack> loaded = new HashMap<>();

        for (String f : families) {
            Path jsonPath = packsDir.resolve(f + "-peripherals.json");
            Path shaPath = packsDir.resolve(f + "-peripherals.sha256");

            if (Files.isRegularFile(jsonPath)) {
                Stm8PeripheralPack pack = Stm8PeripheralPackLoader.load(jsonPath, shaPath, limits, token);
                loaded.put(pack.family().toUpperCase(Locale.ROOT), pack);
            }
        }

        return new Stm8DevicePackRegistry(List.copyOf(loaded.values()));
    }

    public Optional<Stm8PeripheralPack> packForFamily(String family) {
        if (family == null || family.isBlank()) {
            return Optional.empty();
        }
        String f = family.trim().toUpperCase(Locale.ROOT);
        if (f.startsWith("STM8AF") || f.startsWith("STM8AL") || f.equals("STM8A")) {
            return Optional.ofNullable(packsByFamily.getOrDefault("STM8A", packsByFamily.get("STM8S")));
        }
        if (f.startsWith("STM8L")) {
            return Optional.ofNullable(packsByFamily.get("STM8L"));
        }
        if (f.startsWith("STM8T")) {
            // Touch sensing uses STM8S peripheral core
            return Optional.ofNullable(packsByFamily.getOrDefault("STM8T", packsByFamily.get("STM8S")));
        }
        return Optional.ofNullable(packsByFamily.get("STM8S"));
    }

    public Optional<Stm8PeripheralPack> packForPart(Stm8PartRecord part) {
        if (part == null) {
            return Optional.empty();
        }
        return packForFamily(part.family());
    }

    public Stm8PeripheralPack getRequiredPack(String family) throws DiagnosticException {
        return packForFamily(family).orElseThrow(() -> new DiagnosticException(Diagnostic.error(
            DiagnosticCode.STM8_PACK_INVALID,
            "No peripheral pack available for family: " + family,
            null)));
    }

    public Stm8PeripheralPack getRequiredPack(Stm8PartRecord part) throws DiagnosticException {
        Objects.requireNonNull(part, "part must not be null");
        return packForPart(part).orElseThrow(() -> new DiagnosticException(Diagnostic.error(
            DiagnosticCode.STM8_PACK_INVALID,
            "No peripheral pack available for part: " + part.exactPart(),
            null)));
    }

    public int packCount() {
        return packsByFamily.size();
    }
}
