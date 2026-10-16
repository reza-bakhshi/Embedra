package io.github.rezabakhshi.embedra.targets.atmel.catalog;

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
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;

/**
 * Authoritative in-memory catalog registry for Atmel / Microchip microcontrollers.
 */
public final class AtmelCatalogRegistry {

    private static final Path DEFAULT_CATALOG_DIR = Path.of("catalogs/atmel/2026-10-14");

    private static final String CATALOG_FILE = "catalog.json";

    private static final String CHECKSUM_FILE = "catalog.sha256";

    private static final Set<String> FORBIDDEN_PREFIXES = Set.of(
        "AVR", "ATMEL", "MICROCHIP", "ATMEGA", "ATTINY", "AVR-DX", "SAM", "SAMD", "SAME", "SAMS", "SAMV"
    );

    private final Map<String, AtmelPartRecord> partsByName;

    private final List<AtmelPartRecord> partsList;

    public AtmelCatalogRegistry(List<AtmelPartRecord> records) {
        Objects.requireNonNull(records, "records must not be null");
        Map<String, AtmelPartRecord> map = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        List<AtmelPartRecord> list = new ArrayList<>(records.size());
        for (AtmelPartRecord r : records) {
            if (map.put(r.exactPart(), r) != null) {
                throw new IllegalArgumentException("Duplicate exact part in Atmel catalog: " + r.exactPart());
            }
            list.add(r);
        }
        this.partsByName = Collections.unmodifiableMap(map);
        this.partsList = Collections.unmodifiableList(list);
    }

    public static AtmelCatalogRegistry loadDefault() throws DiagnosticException {
        return load(DEFAULT_CATALOG_DIR, ParserLimits.defaults(), CancellationToken.none());
    }

    @SuppressWarnings("unchecked")
    public static AtmelCatalogRegistry load(Path directory, ParserLimits limits, CancellationToken token)
            throws DiagnosticException {
        Objects.requireNonNull(directory, "directory must not be null");
        Objects.requireNonNull(limits, "limits must not be null");
        Objects.requireNonNull(token, "token must not be null");

        token.throwIfCancellationRequested();

        Path catalogPath = directory.resolve(CATALOG_FILE);
        Path checksumPath = directory.resolve(CHECKSUM_FILE);

        if (!Files.isRegularFile(catalogPath)) {
            throw new DiagnosticException(Diagnostic.error(
                DiagnosticCode.ATMEL_CATALOG_INVALID,
                "Atmel catalog file not found: " + catalogPath,
                null));
        }

        byte[] bytes;
        try {
            bytes = Files.readAllBytes(catalogPath);
        } catch (IOException e) {
            throw new DiagnosticException(Diagnostic.error(
                DiagnosticCode.ATMEL_CATALOG_INVALID,
                "Failed to read Atmel catalog: " + e.getMessage(),
                null));
        }

        if (bytes.length > limits.maxInputBytes() || bytes.length > limits.maxAllocationBytes()) {
            throw new DiagnosticException(Diagnostic.error(
                DiagnosticCode.LIMIT_EXCEEDED,
                "Atmel catalog exceeds configured parser size limits",
                null));
        }

        if (Files.isRegularFile(checksumPath)) {
            try {
                String checksumLine = Files.readString(checksumPath, StandardCharsets.UTF_8).trim();
                String expectedSha = checksumLine.split("\\s+")[0].toLowerCase(Locale.ROOT);
                String actualSha = sha256Hex(bytes);
                if (!expectedSha.equals(actualSha)) {
                    throw new DiagnosticException(Diagnostic.error(
                        DiagnosticCode.ATMEL_CATALOG_INTEGRITY_MISMATCH,
                        String.format("Atmel catalog checksum mismatch: expected %s but got %s",
                            expectedSha, actualSha),
                        null));
                }
            } catch (IOException e) {
                throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.ATMEL_CATALOG_INVALID,
                    "Failed to read Atmel catalog checksum: " + e.getMessage(),
                    null));
            }
        }

        token.throwIfCancellationRequested();

        Object parsed;
        try {
            parsed = StrictJsonParser.parse(bytes, limits, token);
        } catch (DiagnosticException e) {
            throw e;
        } catch (Exception e) {
            throw new DiagnosticException(Diagnostic.error(
                DiagnosticCode.ATMEL_CATALOG_INVALID,
                "Failed to parse Atmel catalog JSON: " + e.getMessage(),
                null));
        }

        if (!(parsed instanceof Map<?, ?> rootMap)) {
            throw new DiagnosticException(Diagnostic.error(
                DiagnosticCode.ATMEL_CATALOG_INVALID,
                "Atmel catalog root must be a JSON object",
                null));
        }

        Object partsObj = rootMap.get("parts");
        if (partsObj == null) {
            partsObj = rootMap.get("records");
        }
        if (!(partsObj instanceof List<?> recordsList)) {
            throw new DiagnosticException(Diagnostic.error(
                DiagnosticCode.ATMEL_CATALOG_INVALID,
                "Atmel catalog missing 'parts' or 'records' array",
                null));
        }

        List<AtmelPartRecord> records = new ArrayList<>(recordsList.size());
        for (Object item : recordsList) {
            token.throwIfCancellationRequested();
            if (!(item instanceof Map<?, ?> recordMap)) {
                continue;
            }
            records.add(parseRecord(recordMap));
        }

        return new AtmelCatalogRegistry(records);
    }

    private static AtmelPartRecord parseRecord(Map<?, ?> map) throws DiagnosticException {
        try {
            String exactPart = (String) map.get("exactPart");
            String family = (String) map.get("family");
            String series = (String) map.get("series");
            String core = (String) map.get("core");
            String arch = (String) map.get("arch");
            String ghidraLanguage = (String) map.get("ghidraLanguage");
            String packageCode = (String) map.get("package");
            String datasheet = (String) map.get("datasheet");

            long flashStart = 0L;
            if (map.get("flashRange") instanceof Map<?, ?> fRange) {
                flashStart = parseHex((String) fRange.get("start"));
            }
            long flashBytes = ((Number) map.get("flashBytes")).longValue();

            long ramStart = 0L;
            if (map.get("ramRange") instanceof Map<?, ?> rRange) {
                ramStart = parseHex((String) rRange.get("start"));
            }
            long ramBytes = ((Number) map.get("ramBytes")).longValue();

            long eepromStart = 0L;
            long eepromBytes = 0L;
            if (map.get("eepromBytes") instanceof Number n) {
                eepromBytes = n.longValue();
            }
            if (eepromBytes > 0 && map.get("eepromRange") instanceof Map<?, ?> eRange) {
                eepromStart = parseHex((String) eRange.get("start"));
            }

            long flashDataAliasStart = 0L;
            long flashDataAliasBytes = 0L;
            if (map.get("flashDataAlias") instanceof Map<?, ?> aliasMap) {
                flashDataAliasStart = parseHex((String) aliasMap.get("start"));
                if (aliasMap.get("windowSize") instanceof Number n) {
                    flashDataAliasBytes = n.longValue();
                }
            }

            int vectorCount = ((Number) map.get("vectorCount")).intValue();
            int vectorStrideBytes = ((Number) map.get("vectorStrideBytes")).intValue();
            String vectorInstruction = (String) map.get("vectorInstruction");

            AtmelAddressModel addressModel = AtmelAddressModel.HARVARD_SEPARATE;
            if ("SAM".equalsIgnoreCase(family)) {
                addressModel = AtmelAddressModel.LINEAR_32BIT;
            } else if (flashDataAliasBytes > 0 || "AVR-Dx".equalsIgnoreCase(series)) {
                addressModel = AtmelAddressModel.HARVARD_UNIFIED_DATA_ALIAS;
            }

            Object stateObj = map.get("supportState");
            String stateStr = stateObj != null ? stateObj.toString() : "PLANNED";
            SupportState supportState = SupportState.valueOf(stateStr);

            return new AtmelPartRecord(
                exactPart, family, series, core, arch, ghidraLanguage, addressModel,
                packageCode != null ? packageCode : "UNKNOWN",
                datasheet != null ? datasheet : "Microchip Technical Specification",
                flashStart, flashBytes, ramStart, ramBytes, eepromStart, eepromBytes,
                flashDataAliasStart, flashDataAliasBytes,
                vectorCount, vectorStrideBytes, vectorInstruction != null ? vectorInstruction : "JMP",
                supportState
            );
        } catch (Exception e) {
            throw new DiagnosticException(Diagnostic.error(
                DiagnosticCode.ATMEL_CATALOG_INVALID,
                "Malformed Atmel part record: " + e.getMessage(),
                null));
        }
    }

    private static long parseHex(String hex) {
        if (hex == null || hex.isBlank()) {
            return 0L;
        }
        String clean = hex.trim();
        if (clean.startsWith("0x") || clean.startsWith("0X")) {
            clean = clean.substring(2);
        }
        return Long.parseLong(clean, 16);
    }

    private static String sha256Hex(byte[] bytes) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(md.digest(bytes));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    public Optional<AtmelPartRecord> findPart(String partName) {
        if (partName == null || partName.isBlank()) {
            return Optional.empty();
        }
        String trimmed = partName.trim();
        if (trimmed.contains("*") || trimmed.contains("?")
                || FORBIDDEN_PREFIXES.contains(trimmed.toUpperCase(Locale.ROOT))) {
            return Optional.empty();
        }
        return Optional.ofNullable(partsByName.get(trimmed));
    }

    public AtmelPartRecord getPart(String partName) throws DiagnosticException {
        Objects.requireNonNull(partName, "partName must not be null");
        String trimmed = partName.trim();
        if (trimmed.contains("*") || trimmed.contains("?")) {
            throw new DiagnosticException(Diagnostic.error(
                DiagnosticCode.ATMEL_ENTRY_REJECTED,
                "Wildcard matching forbidden for Atmel exact part: " + partName,
                null));
        }
        if (FORBIDDEN_PREFIXES.contains(trimmed.toUpperCase(Locale.ROOT))) {
            throw new DiagnosticException(Diagnostic.error(
                DiagnosticCode.ATMEL_ENTRY_REJECTED,
                "Generic family prefix cannot be used as exact silicon part: " + partName,
                null));
        }
        AtmelPartRecord record = partsByName.get(trimmed);
        if (record == null) {
            throw new DiagnosticException(Diagnostic.error(
                DiagnosticCode.ATMEL_TARGET_UNSUPPORTED,
                "Unknown Atmel / Microchip part: " + partName,
                null));
        }
        return record;
    }

    public List<AtmelPartRecord> allParts() {
        return partsList;
    }

    public List<AtmelPartRecord> partsByFamily(String family) {
        Objects.requireNonNull(family, "family must not be null");
        return partsList.stream()
            .filter(p -> p.family().equalsIgnoreCase(family))
            .toList();
    }

    public List<AtmelPartRecord> partsBySeries(String series) {
        Objects.requireNonNull(series, "series must not be null");
        return partsList.stream()
            .filter(p -> p.series().equalsIgnoreCase(series))
            .toList();
    }

    public int size() {
        return partsList.size();
    }
}
