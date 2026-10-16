package io.github.rezabakhshi.embedra.targets.stm8.catalog;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.catalog.SupportState;
import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.pack.StrictJsonParser;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.TreeMap;

/**
 * Authoritative in-memory catalog registry for STMicroelectronics STM8 8-bit microcontrollers.
 */
public final class Stm8CatalogRegistry {

    private static final Path DEFAULT_CATALOG_DIR = Path.of("catalogs/stm8/2026-10-13");

    private static final String CATALOG_FILE = "catalog.json";

    private static final String CHECKSUM_FILE = "catalog.sha256";

    private final Map<String, Stm8PartRecord> partsByName;

    private final List<Stm8PartRecord> partsList;

    public Stm8CatalogRegistry(List<Stm8PartRecord> records) {
        Objects.requireNonNull(records, "records must not be null");
        Map<String, Stm8PartRecord> map = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        List<Stm8PartRecord> list = new ArrayList<>(records.size());
        for (Stm8PartRecord r : records) {
            if (map.put(r.exactPart(), r) != null) {
                throw new IllegalArgumentException("Duplicate exact part in STM8 catalog: " + r.exactPart());
            }
            list.add(r);
        }
        this.partsByName = Collections.unmodifiableMap(map);
        this.partsList = Collections.unmodifiableList(list);
    }

    public static Stm8CatalogRegistry loadDefault() throws DiagnosticException {
        return load(DEFAULT_CATALOG_DIR, ParserLimits.defaults(), CancellationToken.none());
    }

    @SuppressWarnings("unchecked")
    public static Stm8CatalogRegistry load(Path directory, ParserLimits limits, CancellationToken token)
            throws DiagnosticException {
        Objects.requireNonNull(directory, "directory must not be null");
        Objects.requireNonNull(limits, "limits must not be null");
        Objects.requireNonNull(token, "token must not be null");

        token.throwIfCancellationRequested();

        Path catalogPath = directory.resolve(CATALOG_FILE);
        Path checksumPath = directory.resolve(CHECKSUM_FILE);

        if (!Files.isRegularFile(catalogPath)) {
            throw new DiagnosticException(Diagnostic.error(
                DiagnosticCode.STM8_CATALOG_INVALID,
                "STM8 catalog file not found: " + catalogPath,
                null));
        }

        byte[] bytes;
        try {
            bytes = Files.readAllBytes(catalogPath);
        } catch (IOException e) {
            throw new DiagnosticException(Diagnostic.error(
                DiagnosticCode.STM8_CATALOG_INVALID,
                "Failed to read STM8 catalog: " + e.getMessage(),
                null));
        }

        if (bytes.length > limits.maxInputBytes() || bytes.length > limits.maxAllocationBytes()) {
            throw new DiagnosticException(Diagnostic.error(
                DiagnosticCode.LIMIT_EXCEEDED,
                "STM8 catalog exceeds configured parser size limits",
                null));
        }

        if (Files.isRegularFile(checksumPath)) {
            try {
                String checksumLine = Files.readString(checksumPath, StandardCharsets.UTF_8).trim();
                String expectedSha = checksumLine.split("\\s+")[0].toLowerCase(Locale.ROOT);
                String actualSha = sha256Hex(bytes);
                if (!expectedSha.equalsIgnoreCase(actualSha)) {
                    throw new DiagnosticException(Diagnostic.error(
                        DiagnosticCode.STM8_CATALOG_INTEGRITY_MISMATCH,
                        "STM8 catalog checksum mismatch: expected " + expectedSha + " but computed " + actualSha,
                        null));
                }
            } catch (IOException e) {
                throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.STM8_CATALOG_INVALID,
                    "Failed to read checksum file: " + e.getMessage(),
                    null));
            }
        }

        Object parsed = StrictJsonParser.parse(bytes, limits, token);
        if (!(parsed instanceof Map<?, ?> rootMap)) {
            throw new DiagnosticException(Diagnostic.error(
                DiagnosticCode.STM8_CATALOG_INVALID,
                "STM8 catalog root must be a JSON object",
                null));
        }

        Object recordsObj = rootMap.get("records");
        if (!(recordsObj instanceof List<?> rawRecords)) {
            throw new DiagnosticException(Diagnostic.error(
                DiagnosticCode.STM8_CATALOG_INVALID,
                "STM8 catalog missing 'records' array",
                null));
        }

        List<Stm8PartRecord> parsedRecords = new ArrayList<>(rawRecords.size());
        for (Object item : rawRecords) {
            if (!(item instanceof Map<?, ?> itemMap)) {
                throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.STM8_CATALOG_INVALID,
                    "Record entry must be a JSON object",
                    null));
            }

            String exactPart = (String) itemMap.get("exactPart");
            String family = (String) itemMap.get("family");
            String subfamily = (String) itemMap.get("subfamily");
            String pkg = (String) itemMap.get("package");
            long flashBytes = ((Number) itemMap.get("flashBytes")).longValue();
            long ramBytes = ((Number) itemMap.get("ramBytes")).longValue();
            long eepromBytes = ((Number) itemMap.get("eepromBytes")).longValue();
            String datasheet = (String) itemMap.get("datasheet");
            Object stateObj = itemMap.get("supportState");
            String stateStr = stateObj != null ? stateObj.toString() : "PLANNED";


            long optionBytes = 128L;
            if ("STM8L".equalsIgnoreCase(family) || "STM8AL".equalsIgnoreCase(subfamily)) {
                optionBytes = 256L;
            }
            long bootRomBytes = 2048L;

            List<String> peripherals = new ArrayList<>();
            Object periphObj = itemMap.get("peripherals");
            if (periphObj instanceof List<?> periphList) {
                for (Object p : periphList) {
                    if (p instanceof String s) {
                        peripherals.add(s);
                    }
                }
            }

            SupportState supportState;
            try {
                supportState = SupportState.valueOf(stateStr.toUpperCase(Locale.ROOT));
            } catch (IllegalArgumentException e) {
                supportState = SupportState.PLANNED;
            }

            parsedRecords.add(new Stm8PartRecord(
                exactPart,
                family,
                subfamily,
                pkg,
                flashBytes,
                ramBytes,
                eepromBytes,
                optionBytes,
                bootRomBytes,
                peripherals,
                supportState,
                datasheet));
        }

        return new Stm8CatalogRegistry(parsedRecords);
    }

    public Optional<Stm8PartRecord> findPart(String partName) {
        if (partName == null || partName.isBlank()) {
            return Optional.empty();
        }
        String trimmed = partName.trim();
        // Reject wildcards and regex characters per STM8-007
        if (trimmed.contains("*") || trimmed.contains("?") || trimmed.contains("[") || trimmed.contains("+")) {
            return Optional.empty();
        }
        return Optional.ofNullable(partsByName.get(trimmed));
    }

    public Stm8PartRecord getRequiredPart(String partName) throws DiagnosticException {
        return findPart(partName).orElseThrow(() -> new DiagnosticException(Diagnostic.error(
            DiagnosticCode.STM8_TARGET_UNSUPPORTED,
            "Exact STM8 part not found in catalog allowlist: " + partName,
            null)));
    }

    public List<Stm8PartRecord> listParts() {
        return partsList;
    }

    public List<Stm8PartRecord> listPartsByFamily(String family) {
        if (family == null || family.isBlank()) {
            return List.of();
        }
        String f = family.trim().toUpperCase(Locale.ROOT);
        return partsList.stream()
            .filter(p -> p.family().equalsIgnoreCase(f) || p.subfamily().toUpperCase(Locale.ROOT).startsWith(f))
            .toList();
    }

    public int partCount() {
        return partsList.size();
    }

    private static String sha256Hex(byte[] bytes) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(bytes);
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 algorithm missing", e);
        }
    }
}
