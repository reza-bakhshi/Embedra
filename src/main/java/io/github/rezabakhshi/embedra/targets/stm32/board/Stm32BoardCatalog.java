package io.github.rezabakhshi.embedra.targets.stm32.board;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.core.io.AddressRange;
import io.github.rezabakhshi.embedra.core.stm32.input.Stm32PartSelection;
import io.github.rezabakhshi.embedra.pack.StrictJsonParser;
import io.github.rezabakhshi.embedra.targets.stm32.catalog.Stm32CuratedPartIds;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Digest-pinned, reviewed STM32 board-profile snapshot for the curated selection.
 *
 * <p>Loading verifies the exact snapshot digest, the pinned curated selection,
 * the board-index digest, and every record's schema before exposing profiles.
 * A profile resolves to an exact MCU only by its explicit exact part id; no
 * family, wildcard, or neighbouring board is ever substituted, and an
 * unavailable profile stays explicit with a reason and no external data.</p>
 */
public final class Stm32BoardCatalog {
    /** SHA-256 of the shipped board-profile snapshot. */
    public static final String SHA256 =
        "78a3e0e41cc14585ad3c4140aed80fff6d53fcd367d6beec3d2cc787950c75f3";

    /** SHA-256 of the reviewed board-part index used to link boards to exact parts. */
    public static final String BOARD_INDEX_SHA256 =
        "2b9c7c2cc5e2838c50190a507cc0d96792d3a3e5eba8a5aee4e21d50cc77b6a7";

    private static final String SCHEMA = "urn:embedra:schema:stm32-board-profiles:1";

    private static final String EXTERNAL_ADDRESS_SPACE = "ext-mem";

    private static final Set<String> ROOT_FIELDS = Set.of("$schema", "curatedCatalogSha256",
        "selectionSha256", "boardIndexSha256", "reviewedProfiles", "profiles");

    private static final Set<String> PROFILE_FIELDS = Set.of("board", "category", "exactPart",
        "status", "sourceIndexSha256", "boardSource", "bsp", "cmsisFamily", "externalRegions",
        "bootOffsets", "reason");

    private static final Set<String> REGION_FIELDS = Set.of("id", "kind", "controller", "device",
        "start", "size", "writable", "startEvidence", "sizeEvidence");

    private static final Set<String> BOARD_SOURCE_FIELDS = Set.of("sourcePath", "sourceSha256");

    private static final Set<String> BSP_FIELDS = Set.of("repository", "revision", "note");

    private static final Set<String> BOOT_FIELDS = Set.of("id", "description", "offset");

    private final List<Stm32BoardProfile> profiles;

    private Stm32BoardCatalog(List<Stm32BoardProfile> profiles) {
        this.profiles = List.copyOf(profiles);
    }

    public static Stm32BoardCatalog load(Path path, Stm32PartSelection selection,
            ParserLimits limits, CancellationToken token)
            throws IOException, DiagnosticException {
        Objects.requireNonNull(path, "path");
        Objects.requireNonNull(selection, "selection");
        Objects.requireNonNull(limits, "limits");
        Objects.requireNonNull(token, "token");
        token.throwIfCancellationRequested();
        if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("STM32 board-profile path is not a regular file");
        }
        long size = Files.size(path);
        if (size > limits.maxInputBytes() || size > limits.maxAllocationBytes()) {
            throw new IOException("STM32 board profiles exceed parser limits");
        }
        byte[] input = Files.readAllBytes(path);
        token.throwIfCancellationRequested();
        if (!SHA256.equals(sha256(input))) {
            throw new IOException("STM32 board-profile digest mismatch");
        }
        try {
            Map<?, ?> root = (Map<?, ?>) StrictJsonParser.parse(input, limits, token);
            if (!SCHEMA.equals(root.get("$schema"))) {
                throw new IOException("STM32 board-profile schema mismatch");
            }
            Map<String, Object> typed = typed(root);
            if (!typed.keySet().equals(ROOT_FIELDS)
                    || !Stm32CuratedPartIds.SELECTION_SHA256
                        .equals(typed.get("selectionSha256"))
                    || !BOARD_INDEX_SHA256.equals(typed.get("boardIndexSha256"))) {
                throw new IOException("STM32 board-profile root fields or pins mismatch");
            }
            List<Stm32BoardProfile> profiles = new ArrayList<>();
            int reviewed = 0;
            for (Object value : typedList(typed.get("profiles"))) {
                Stm32BoardProfile profile = profile(typedMap(value, PROFILE_FIELDS), selection);
                if (profile.reviewed()) {
                    reviewed++;
                }
                profiles.add(profile);
            }
            if (!(typed.get("reviewedProfiles") instanceof Long expected)
                    || expected != reviewed) {
                throw new IOException("Board-profile reviewed count mismatch");
            }
            return new Stm32BoardCatalog(profiles);
        }
        catch (ClassCastException | NullPointerException | IllegalArgumentException exception) {
            throw new IOException("STM32 board profiles are invalid", exception);
        }
    }

    public List<Stm32BoardProfile> profiles() {
        return profiles.stream()
            .sorted(Comparator.comparing(Stm32BoardProfile::exactPart)
                .thenComparing(profile -> profile.board() == null ? "" : profile.board()))
            .toList();
    }

    public int size() {
        return profiles.size();
    }

    /** All reviewed profiles for an exact part; never a family-level match. */
    public List<Stm32BoardProfile> forPart(String exactPart) {
        Objects.requireNonNull(exactPart, "exactPart");
        return profiles.stream().filter(profile -> profile.exactPart().equals(exactPart))
            .sorted(Comparator.comparing(profile ->
                profile.board() == null ? "" : profile.board()))
            .toList();
    }

    /** The single reviewed profile for an exact part, or an explicit failure. */
    public Stm32BoardProfile requireProfiles(String exactPart) {
        List<Stm32BoardProfile> matches = forPart(exactPart);
        if (matches.isEmpty()) {
            throw new IllegalArgumentException("No reviewed board profile for " + exactPart);
        }
        if (matches.size() > 1) {
            throw new IllegalArgumentException(
                "Multiple board profiles for " + exactPart + "; select a board explicitly");
        }
        return matches.get(0);
    }

    private static Stm32BoardProfile profile(Map<String, Object> value,
            Stm32PartSelection selection) throws IOException {
        String exactPart = string(value, "exactPart");
        if (!selection.containsExactPart(exactPart)) {
            throw new IOException("Board profile is not a curated exact part: " + exactPart);
        }
        Stm32BoardProfile.Status status;
        try {
            status = Stm32BoardProfile.Status.valueOf(string(value, "status"));
        }
        catch (IllegalArgumentException exception) {
            throw new IOException("Unknown board-profile status");
        }
        if (!BOARD_INDEX_SHA256.equals(string(value, "sourceIndexSha256"))) {
            throw new IOException("Board profile does not cite the pinned board index");
        }
        Stm32BoardProfile.BoardSource source = null;
        if (value.get("boardSource") != null) {
            Map<String, Object> raw = typedMap(value.get("boardSource"), BOARD_SOURCE_FIELDS);
            source = new Stm32BoardProfile.BoardSource(
                string(raw, "sourcePath"), string(raw, "sourceSha256"));
        }
        Stm32BoardProfile.BoardBsp bsp = null;
        if (value.get("bsp") != null) {
            Map<String, Object> raw = typedMap(value.get("bsp"), BSP_FIELDS);
            bsp = new Stm32BoardProfile.BoardBsp(string(raw, "repository"),
                string(raw, "revision"), string(raw, "note"));
        }
        List<Stm32BoardProfile.ExternalRegion> regions = new ArrayList<>();
        for (Object object : typedList(value.get("externalRegions"))) {
            Map<String, Object> raw = typedMap(object, REGION_FIELDS);
            Stm32BoardProfile.Kind kind;
            try {
                kind = Stm32BoardProfile.Kind.valueOf(string(raw, "kind"));
            }
            catch (IllegalArgumentException exception) {
                throw new IOException("Unknown external region kind");
            }
            long start = longValue(raw, "start");
            long size = longValue(raw, "size");
            Object writable = raw.get("writable");
            if (!(writable instanceof Boolean flag)) {
                throw new IOException("External region writable flag must be boolean");
            }
            regions.add(new Stm32BoardProfile.ExternalRegion(string(raw, "id"), kind,
                string(raw, "controller"), string(raw, "device"),
                new AddressRange(EXTERNAL_ADDRESS_SPACE, start, size), flag,
                string(raw, "startEvidence"), string(raw, "sizeEvidence")));
        }
        List<Stm32BoardProfile.BootOffset> boots = new ArrayList<>();
        for (Object object : typedList(value.get("bootOffsets"))) {
            Map<String, Object> raw = typedMap(object, BOOT_FIELDS);
            boots.add(new Stm32BoardProfile.BootOffset(string(raw, "id"),
                string(raw, "description"), longValue(raw, "offset")));
        }
        return new Stm32BoardProfile(nullableString(value.get("board")),
            nullableString(value.get("category")), exactPart, status, source, bsp,
            nullableString(value.get("cmsisFamily")), regions, boots,
            nullableString(value.get("reason")));
    }

    private static long longValue(Map<String, Object> map, String key) throws IOException {
        Object value = map.get(key);
        if (!(value instanceof Long number)) {
            throw new IOException("Board-profile field must be an integer: " + key);
        }
        return number;
    }

    private static Map<String, Object> typedMap(Object value, Set<String> fields)
            throws IOException {
        if (!(value instanceof Map<?, ?> map)) {
            throw new IOException("Board-profile object is missing");
        }
        Map<String, Object> typed = typed(map);
        if (!typed.keySet().equals(fields)) {
            throw new IOException("Board-profile object fields do not match schema");
        }
        return typed;
    }

    private static Map<String, Object> typed(Map<?, ?> map) throws IOException {
        Map<String, Object> result = new LinkedHashMap<>();
        for (Map.Entry<?, ?> entry : map.entrySet()) {
            if (!(entry.getKey() instanceof String key)) {
                throw new IOException("Board-profile keys must be strings");
            }
            result.put(key, entry.getValue());
        }
        return result;
    }

    private static List<Object> typedList(Object value) throws IOException {
        if (!(value instanceof List<?> list)) {
            throw new IOException("Board-profile value must be an array");
        }
        return new ArrayList<>(list);
    }

    private static String string(Map<String, Object> map, String key) throws IOException {
        Object value = map.get(key);
        if (!(value instanceof String text)) {
            throw new IOException("Board-profile field must be a string: " + key);
        }
        return text;
    }

    private static String nullableString(Object value) throws IOException {
        if (value == null) {
            return null;
        }
        if (!(value instanceof String text)) {
            throw new IOException("Board-profile field must be a string or null");
        }
        return text;
    }

    private static String sha256(byte[] input) {
        try {
            return HexFormat.of().formatHex(
                MessageDigest.getInstance("SHA-256").digest(input));
        }
        catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 unavailable", exception);
        }
    }
}
