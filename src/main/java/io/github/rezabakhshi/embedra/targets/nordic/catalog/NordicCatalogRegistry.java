package io.github.rezabakhshi.embedra.targets.nordic.catalog;

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
 * Authoritative in-memory catalog registry for Nordic Semiconductor SoCs and microcontrollers.
 */
public final class NordicCatalogRegistry {

    private static final Path DEFAULT_CATALOG_DIR = Path.of("catalogs/nordic/2026-10-13");

    private static final String CATALOG_FILE = "catalog.json";

    private static final String CHECKSUM_FILE = "catalog.sha256";

    private static final Set<String> FORBIDDEN_PREFIXES = Set.of(
        "NRF51", "NRF52", "NRF53", "NRF54", "NRF91"
    );

    private final Map<String, NordicPartRecord> partsByName;

    private final List<NordicPartRecord> partsList;

    public NordicCatalogRegistry(List<NordicPartRecord> records) {
        Objects.requireNonNull(records, "records must not be null");
        Map<String, NordicPartRecord> map = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        List<NordicPartRecord> list = new ArrayList<>(records.size());
        for (NordicPartRecord r : records) {
            if (map.put(r.exactPart(), r) != null) {
                throw new IllegalArgumentException("Duplicate exact part in Nordic catalog: " + r.exactPart());
            }
            list.add(r);
        }
        this.partsByName = Collections.unmodifiableMap(map);
        this.partsList = Collections.unmodifiableList(list);
    }

    public static NordicCatalogRegistry loadDefault() throws DiagnosticException {
        return load(DEFAULT_CATALOG_DIR, ParserLimits.defaults(), CancellationToken.none());
    }

    @SuppressWarnings("unchecked")
    public static NordicCatalogRegistry load(Path directory, ParserLimits limits, CancellationToken token)
            throws DiagnosticException {
        Objects.requireNonNull(directory, "directory must not be null");
        Objects.requireNonNull(limits, "limits must not be null");
        Objects.requireNonNull(token, "token must not be null");

        token.throwIfCancellationRequested();

        Path catalogPath = directory.resolve(CATALOG_FILE);
        Path checksumPath = directory.resolve(CHECKSUM_FILE);

        if (!Files.isRegularFile(catalogPath)) {
            throw new DiagnosticException(Diagnostic.error(
                DiagnosticCode.NORDIC_CATALOG_INVALID,
                "Nordic catalog file not found: " + catalogPath,
                null));
        }

        byte[] bytes;
        try {
            bytes = Files.readAllBytes(catalogPath);
        } catch (IOException e) {
            throw new DiagnosticException(Diagnostic.error(
                DiagnosticCode.NORDIC_CATALOG_INVALID,
                "Failed to read Nordic catalog: " + e.getMessage(),
                null));
        }

        if (bytes.length > limits.maxInputBytes() || bytes.length > limits.maxAllocationBytes()) {
            throw new DiagnosticException(Diagnostic.error(
                DiagnosticCode.LIMIT_EXCEEDED,
                "Nordic catalog exceeds configured parser size limits",
                null));
        }

        if (Files.isRegularFile(checksumPath)) {
            try {
                String checksumLine = Files.readString(checksumPath, StandardCharsets.UTF_8).trim();
                String expectedSha = checksumLine.split("\\s+")[0].toLowerCase(Locale.ROOT);
                String actualSha = sha256Hex(bytes);
                if (!expectedSha.equals(actualSha)) {
                    throw new DiagnosticException(Diagnostic.error(
                        DiagnosticCode.NORDIC_CATALOG_INTEGRITY_MISMATCH,
                        String.format("Nordic catalog checksum mismatch: expected %s but got %s",
                            expectedSha, actualSha),
                        null));
                }
            } catch (IOException e) {
                throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.NORDIC_CATALOG_INVALID,
                    "Failed to read Nordic catalog checksum: " + e.getMessage(),
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
                DiagnosticCode.NORDIC_CATALOG_INVALID,
                "Failed to parse Nordic catalog JSON: " + e.getMessage(),
                null));
        }

        if (!(parsed instanceof Map<?, ?> rootMap)) {
            throw new DiagnosticException(Diagnostic.error(
                DiagnosticCode.NORDIC_CATALOG_INVALID,
                "Nordic catalog root must be a JSON object",
                null));
        }

        Object recordsObj = rootMap.get("records");
        if (!(recordsObj instanceof List<?> recordsList)) {
            throw new DiagnosticException(Diagnostic.error(
                DiagnosticCode.NORDIC_CATALOG_INVALID,
                "Nordic catalog missing 'records' array",
                null));
        }

        List<NordicPartRecord> records = new ArrayList<>(recordsList.size());
        for (Object item : recordsList) {
            token.throwIfCancellationRequested();
            if (!(item instanceof Map<?, ?> recordMap)) {
                continue;
            }
            records.add(parseRecord(recordMap));
        }

        return new NordicCatalogRegistry(records);
    }

    private static NordicPartRecord parseRecord(Map<?, ?> map) throws DiagnosticException {
        try {
            String exactPart = (String) map.get("exactPart");
            String series = (String) map.get("series");
            String subfamily = (String) map.get("subfamily");
            String packageCode = (String) map.get("package");
            String core = (String) map.get("core");
            boolean fpu = Boolean.TRUE.equals(map.get("fpu"));
            long flashBytes = ((Number) map.get("flashBytes")).longValue();
            long ramBytes = ((Number) map.get("ramBytes")).longValue();

            long ficrStart = 0x10000000L;
            long ficrEnd = 0x100000FFL;
            if (map.get("ficrRange") instanceof Map<?, ?> ficrMap) {
                ficrStart = parseHex((String) ficrMap.get("start"));
                ficrEnd = parseHex((String) ficrMap.get("end"));
            }
            long ficrBytes = ficrEnd - ficrStart + 1L;

            long uicrStart = 0x10001000L;
            long uicrEnd = 0x100013FFL;
            if (map.get("uicrRange") instanceof Map<?, ?> uicrMap) {
                uicrStart = parseHex((String) uicrMap.get("start"));
                uicrEnd = parseHex((String) uicrMap.get("end"));
            }
            long uicrBytes = uicrEnd - uicrStart + 1L;

            long periStart = 0x40000000L;
            long periEnd = 0x5FFFFFFFL;
            if (map.get("peripheralsRange") instanceof Map<?, ?> periMap) {
                periStart = parseHex((String) periMap.get("start"));
                periEnd = parseHex((String) periMap.get("end"));
            }
            long periBytes = periEnd - periStart + 1L;

            String cryptoCellName = null;
            long cryptoCellBase = 0L;
            long cryptoCellSize = 0L;
            Object ccObj = map.get("cryptoCell");
            if (ccObj instanceof Map<?, ?> ccMap) {
                cryptoCellName = (String) ccMap.get("name");
                cryptoCellBase = parseHex((String) ccMap.get("base"));
                cryptoCellSize = ((Number) ccMap.get("size")).longValue();
            }

            boolean trustZone = Boolean.TRUE.equals(map.get("trustZone"));
            boolean dualCore = Boolean.TRUE.equals(map.get("dualCore"));

            Object stateObj = map.get("supportState");
            String stateStr = stateObj != null ? stateObj.toString() : "PLANNED";
            SupportState supportState = SupportState.valueOf(stateStr);

            Object dsObj = map.get("datasheet");
            String datasheet = dsObj != null ? dsObj.toString() : "Nordic Semiconductor Product Specification";

            return new NordicPartRecord(
                exactPart, series, subfamily, packageCode, core, fpu,
                flashBytes, ramBytes,
                ficrStart, ficrBytes, uicrStart, uicrBytes,
                periStart, periBytes,
                cryptoCellName, cryptoCellBase, cryptoCellSize,
                trustZone, dualCore, supportState, datasheet
            );
        } catch (Exception e) {
            throw new DiagnosticException(Diagnostic.error(
                DiagnosticCode.NORDIC_CATALOG_INVALID,
                "Malformed Nordic catalog record: " + e.getMessage(),
                null));
        }
    }

    private static long parseHex(String hex) {
        if (hex == null) {
            return 0L;
        }
        String clean = hex.trim();
        if (clean.startsWith("0x") || clean.startsWith("0X")) {
            clean = clean.substring(2);
        }
        return Long.parseLong(clean, 16);
    }

    private static String sha256Hex(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(md.digest(data));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    public Optional<NordicPartRecord> findExactPart(String exactPart) {
        if (exactPart == null || exactPart.isBlank()) {
            return Optional.empty();
        }
        String trimmed = exactPart.trim();
        if (trimmed.contains("*") || trimmed.contains("?")) {
            return Optional.empty();
        }
        if (FORBIDDEN_PREFIXES.contains(trimmed.toUpperCase(Locale.ROOT))) {
            return Optional.empty();
        }
        return Optional.ofNullable(partsByName.get(trimmed));
    }

    public List<NordicPartRecord> allParts() {
        return partsList;
    }

    public List<NordicPartRecord> partsBySeries(String series) {
        Objects.requireNonNull(series, "series must not be null");
        return partsList.stream()
            .filter(p -> p.series().equalsIgnoreCase(series))
            .toList();
    }

    public int size() {
        return partsList.size();
    }
}
