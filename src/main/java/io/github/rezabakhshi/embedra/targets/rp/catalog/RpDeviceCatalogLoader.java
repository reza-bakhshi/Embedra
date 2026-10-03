package io.github.rezabakhshi.embedra.targets.rp.catalog;

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
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Bounded, integrity-first loader for the offline Raspberry Pi silicon and board catalog.
 */
public final class RpDeviceCatalogLoader {

    private static final String CATALOG_JSON = "catalog.json";

    private static final String CATALOG_SHA256 = "catalog.sha256";

    private static final String BOARDS_JSON = "board-profiles.json";

    private static final String BOARDS_SHA256 = "board-profiles.sha256";

    private static final String EXPECTED_CATALOG_SCHEMA = "urn:embedra:schema:rp-catalog:1";

    private static final String EXPECTED_BOARD_SCHEMA = "urn:embedra:schema:rp-board-profiles:1";

    private RpDeviceCatalogLoader() {
    }

    public static RpDeviceCatalog loadDefault() throws DiagnosticException {
        return load(Path.of("catalogs/rp/2026-10-02"), ParserLimits.defaults(), CancellationToken.none());
    }

    public static RpDeviceCatalog load(Path directory, ParserLimits limits, CancellationToken token)
            throws DiagnosticException {
        Objects.requireNonNull(directory, "directory must not be null");
        Objects.requireNonNull(limits, "limits must not be null");
        Objects.requireNonNull(token, "token must not be null");

        token.throwIfCancellationRequested();

        Path catalogPath = directory.resolve(CATALOG_JSON);
        Path catalogShaPath = directory.resolve(CATALOG_SHA256);
        Path boardsPath = directory.resolve(BOARDS_JSON);
        Path boardsShaPath = directory.resolve(BOARDS_SHA256);

        validateSafeFile(directory, catalogPath);
        validateSafeFile(directory, catalogShaPath);
        validateSafeFile(directory, boardsPath);
        validateSafeFile(directory, boardsShaPath);

        byte[] catalogBytes = readBounded(catalogPath, limits, token);
        String expectedCatalogSha = readChecksum(catalogShaPath, limits, token);
        String actualCatalogSha = sha256(catalogBytes);
        if (!MessageDigest.isEqual(expectedCatalogSha.getBytes(StandardCharsets.US_ASCII),
                actualCatalogSha.getBytes(StandardCharsets.US_ASCII))) {
            throw failure(DiagnosticCode.RP_CATALOG_INTEGRITY_MISMATCH,
                    "RP silicon catalog content does not match catalog.sha256");
        }

        byte[] boardsBytes = readBounded(boardsPath, limits, token);
        String expectedBoardsSha = readChecksum(boardsShaPath, limits, token);
        String actualBoardsSha = sha256(boardsBytes);
        if (!MessageDigest.isEqual(expectedBoardsSha.getBytes(StandardCharsets.US_ASCII),
                actualBoardsSha.getBytes(StandardCharsets.US_ASCII))) {
            throw failure(DiagnosticCode.RP_CATALOG_INTEGRITY_MISMATCH,
                    "RP board profiles content does not match board-profiles.sha256");
        }

        Object parsedCatalog = parseJson(catalogBytes, limits, token, "RP silicon catalog");
        Object parsedBoards = parseJson(boardsBytes, limits, token, "RP board profiles");

        List<RpSiliconRecord> siliconRecords = parseSiliconCatalog(parsedCatalog);
        List<RpBoardProfile> boardProfiles = parseBoardProfiles(parsedBoards);

        return new RpDeviceCatalog(siliconRecords, boardProfiles, actualCatalogSha, actualBoardsSha);
    }

    @SuppressWarnings("unchecked")
    private static List<RpSiliconRecord> parseSiliconCatalog(Object root) throws DiagnosticException {
        if (!(root instanceof Map<?, ?> map)) {
            throw failure(DiagnosticCode.RP_CATALOG_INVALID, "Catalog root must be a JSON object");
        }

        Object schema = map.get("$schema");
        if (!EXPECTED_CATALOG_SCHEMA.equals(schema)) {
            throw failure(DiagnosticCode.RP_CATALOG_INVALID, "Unsupported catalog schema: " + schema);
        }

        Object recordsObj = map.get("records");
        if (!(recordsObj instanceof List<?> recordsList)) {
            throw failure(DiagnosticCode.RP_CATALOG_INVALID, "Catalog records must be a JSON array");
        }

        List<RpSiliconRecord> records = new ArrayList<>();
        for (Object item : recordsList) {
            if (!(item instanceof Map<?, ?> recordMap)) {
                throw failure(DiagnosticCode.RP_CATALOG_INVALID, "Catalog record must be an object");
            }
            records.add(parseSiliconRecord((Map<String, Object>) recordMap));
        }
        return records;
    }

    @SuppressWarnings("unchecked")
    private static RpSiliconRecord parseSiliconRecord(Map<String, Object> map) throws DiagnosticException {
        try {
            String recordId = requireString(map, "recordId");
            String exactPart = requireString(map, "exactPart");
            String series = requireString(map, "series");
            String vendor = requireString(map, "vendor");
            String packageName = requireString(map, "package");
            String dimensions = requireString(map, "dimensions");
            int gpioCount = ((Number) requireField(map, "gpioCount")).intValue();
            long internalFlashBytes = ((Number) requireField(map, "internalFlashBytes")).longValue();
            long externalXipLimitBytes = ((Number) requireField(map, "externalXipLimitBytes")).longValue();
            long sramBytes = ((Number) requireField(map, "sramBytes")).longValue();

            List<RpSramBank> sramBanks = new ArrayList<>();
            Object banksObj = map.get("sramBanks");
            if (banksObj instanceof List<?> banksList) {
                for (Object b : banksList) {
                    if (b instanceof Map<?, ?> bMap) {
                        String bName = (String) bMap.get("name");
                        long bBase = ((Number) bMap.get("baseAddress")).longValue();
                        long bSize = ((Number) bMap.get("sizeBytes")).longValue();
                        boolean bStriped = Boolean.TRUE.equals(bMap.get("striped"));
                        sramBanks.add(new RpSramBank(bName, bBase, bSize, bStriped));
                    }
                }
            }

            long bootRomBytes = ((Number) requireField(map, "bootRomBytes")).longValue();
            long bootRomBase = ((Number) requireField(map, "bootRomBase")).longValue();
            long flashXipBase = ((Number) requireField(map, "flashXipBase")).longValue();
            int applicationCoreCount = ((Number) requireField(map, "applicationCoreCount")).intValue();

            List<String> bootArchitectures = parseStringList(map.get("bootArchitectures"));
            String architectureSelectionMode = requireString(map, "architectureSelectionMode");
            int pioBlocks = ((Number) requireField(map, "pioBlocks")).intValue();
            int pioStateMachinesPerBlock = ((Number) requireField(map, "pioStateMachinesPerBlock")).intValue();
            boolean hasAtomicAliases = Boolean.TRUE.equals(map.get("hasAtomicAliases"));
            long atomicAliasBase = ((Number) requireField(map, "atomicAliasBase")).longValue();
            long sioBase = ((Number) requireField(map, "sioBase")).longValue();

            List<String> securityCapabilities = parseStringList(map.get("securityCapabilities"));
            List<String> peripheralNames = parseStringList(map.get("peripheralNames"));
            String supportStateStr = requireString(map, "supportState");
            SupportState supportState = SupportState.valueOf(supportStateStr);

            return new RpSiliconRecord(
                    recordId, exactPart, series, vendor, packageName, dimensions,
                    gpioCount, internalFlashBytes, externalXipLimitBytes, sramBytes,
                    sramBanks, bootRomBytes, bootRomBase, flashXipBase, applicationCoreCount,
                    bootArchitectures, architectureSelectionMode, pioBlocks, pioStateMachinesPerBlock,
                    hasAtomicAliases, atomicAliasBase, sioBase, securityCapabilities,
                    peripheralNames, supportState);
        } catch (DiagnosticException e) {
            throw e;
        } catch (Exception e) {
            throw failure(DiagnosticCode.RP_CATALOG_INVALID, "Malformed silicon record: " + e.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    private static List<RpBoardProfile> parseBoardProfiles(Object root) throws DiagnosticException {
        if (!(root instanceof Map<?, ?> map)) {
            throw failure(DiagnosticCode.RP_CATALOG_INVALID, "Board profiles root must be a JSON object");
        }

        Object schema = map.get("$schema");
        if (!EXPECTED_BOARD_SCHEMA.equals(schema)) {
            throw failure(DiagnosticCode.RP_CATALOG_INVALID, "Unsupported board schema: " + schema);
        }

        Object profilesObj = map.get("profiles");
        if (!(profilesObj instanceof List<?> profilesList)) {
            throw failure(DiagnosticCode.RP_CATALOG_INVALID, "Profiles must be a JSON array");
        }

        List<RpBoardProfile> profiles = new ArrayList<>();
        for (Object item : profilesList) {
            if (!(item instanceof Map<?, ?> profileMap)) {
                throw failure(DiagnosticCode.RP_CATALOG_INVALID, "Profile must be an object");
            }
            profiles.add(parseBoardProfile((Map<String, Object>) profileMap));
        }
        return profiles;
    }

    @SuppressWarnings("unchecked")
    private static RpBoardProfile parseBoardProfile(Map<String, Object> map) throws DiagnosticException {
        try {
            String profileId = requireString(map, "profileId");
            String boardName = requireString(map, "boardName");
            String vendor = requireString(map, "vendor");
            String siliconPart = requireString(map, "siliconPart");
            long externalFlashBytes = ((Number) requireField(map, "externalFlashBytes")).longValue();
            String externalFlashChip = requireString(map, "externalFlashChip");
            String externalFlashInterface = requireString(map, "externalFlashInterface");

            RpWirelessInfo wirelessInfo = null;
            Object wirelessObj = map.get("wirelessChip");
            if (wirelessObj instanceof Map<?, ?> wMap) {
                String model = (String) wMap.get("model");
                List<String> ifaces = parseStringList(wMap.get("interfaces"));
                String wifi = (String) wMap.get("wifi");
                String bt = (String) wMap.get("bluetooth");
                wirelessInfo = new RpWirelessInfo(model, ifaces, wifi, bt);
            }

            Integer ledGpio = map.get("ledGpio") instanceof Number n ? n.intValue() : null;
            String supportStateStr = requireString(map, "supportState");
            SupportState supportState = SupportState.valueOf(supportStateStr);
            String docUrl = (String) map.get("documentationUrl");

            return new RpBoardProfile(
                    profileId, boardName, vendor, siliconPart, externalFlashBytes,
                    externalFlashChip, externalFlashInterface, wirelessInfo, ledGpio,
                    supportState, docUrl);
        } catch (DiagnosticException e) {
            throw e;
        } catch (Exception e) {
            throw failure(DiagnosticCode.RP_CATALOG_INVALID, "Malformed board profile: " + e.getMessage());
        }
    }

    private static Object parseJson(byte[] bytes, ParserLimits limits, CancellationToken token, String description)
            throws DiagnosticException {
        try {
            return StrictJsonParser.parse(bytes, limits, token);
        } catch (DiagnosticException exception) {
            if (exception.diagnostic().code() == DiagnosticCode.LIMIT_EXCEEDED
                    || exception.diagnostic().code() == DiagnosticCode.CANCELLED) {
                throw exception;
            }
            throw failure(DiagnosticCode.RP_CATALOG_INVALID, description + " JSON is invalid");
        }
    }

    private static List<String> parseStringList(Object obj) {
        if (!(obj instanceof List<?> list)) {
            return List.of();
        }
        List<String> result = new ArrayList<>();
        for (Object item : list) {
            if (item != null) {
                result.add(item.toString());
            }
        }
        return result;
    }

    private static Object requireField(Map<String, Object> map, String key) throws DiagnosticException {
        Object val = map.get(key);
        if (val == null) {
            throw failure(DiagnosticCode.RP_CATALOG_INVALID, "Missing mandatory field: " + key);
        }
        return val;
    }

    private static String requireString(Map<String, Object> map, String key) throws DiagnosticException {
        Object val = requireField(map, key);
        if (!(val instanceof String s) || s.isBlank()) {
            throw failure(DiagnosticCode.RP_CATALOG_INVALID, "Field " + key + " must be a non-blank string");
        }
        return s;
    }

    private static void validateSafeFile(Path directory, Path target) throws DiagnosticException {
        try {
            if (!Files.exists(target, LinkOption.NOFOLLOW_LINKS)
                    || Files.isSymbolicLink(target)
                    || !Files.isRegularFile(target, LinkOption.NOFOLLOW_LINKS)) {
                throw failure(DiagnosticCode.RP_CATALOG_INVALID,
                        "Target must be a regular non-symlink file: " + target);
            }
            if (!target.toRealPath().startsWith(directory.toRealPath())) {
                throw failure(DiagnosticCode.RP_CATALOG_INVALID, "Target escapes directory boundary: " + target);
            }
        } catch (IOException e) {
            throw failure(DiagnosticCode.RP_CATALOG_INVALID, "Failed to validate file: " + target);
        }
    }

    private static byte[] readBounded(Path path, ParserLimits limits, CancellationToken token)
            throws DiagnosticException {
        token.throwIfCancellationRequested();
        try {
            long size = Files.size(path);
            if (size > limits.maxInputBytes() || size > limits.maxAllocationBytes()) {
                throw failure(DiagnosticCode.LIMIT_EXCEEDED, "File exceeds max payload size: " + size);
            }
            byte[] bytes = Files.readAllBytes(path);
            token.throwIfCancellationRequested();
            return bytes;
        } catch (IOException e) {
            throw failure(DiagnosticCode.RP_CATALOG_INVALID, "Failed to read file: " + path);
        }
    }

    private static String readChecksum(Path path, ParserLimits limits, CancellationToken token)
            throws DiagnosticException {
        byte[] bytes = readBounded(path, limits, token);
        String content = new String(bytes, StandardCharsets.UTF_8).trim();
        String[] parts = content.split("\\s+");
        if (parts.length == 0 || parts[0].length() != 64) {
            throw failure(DiagnosticCode.RP_CATALOG_INTEGRITY_MISMATCH, "Invalid sha256 checksum file");
        }
        return parts[0].toLowerCase();
    }

    private static String sha256(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(data);
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    private static DiagnosticException failure(DiagnosticCode code, String message) {
        return new DiagnosticException(Diagnostic.error(code, message, null));
    }
}
