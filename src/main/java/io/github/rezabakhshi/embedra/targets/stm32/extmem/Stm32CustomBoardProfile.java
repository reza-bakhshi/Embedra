package io.github.rezabakhshi.embedra.targets.stm32.extmem;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.core.io.AddressRange;
import io.github.rezabakhshi.embedra.core.model.Evidence;
import io.github.rezabakhshi.embedra.core.model.EvidenceKind;
import io.github.rezabakhshi.embedra.core.stm32.input.Stm32PartSelection;
import io.github.rezabakhshi.embedra.pack.StrictJsonParser;
import io.github.rezabakhshi.embedra.targets.stm32.board.Stm32BoardProfile;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * A confirmed user-supplied board profile (STM-016).
 *
 * <p>A custom profile layers external flash/RAM regions and optional boot
 * offsets over one exact curated part without changing the underlying MCU pack
 * and without touching any pinned snapshot. The confirmation evidence is a
 * mandatory {@code USER_ASSERTION}: the user owns every fact and Embedra never
 * fabricates a controller, window, size, permission, or board link. Regions
 * reuse the T042 {@code ExternalRegion} contract unchanged, so a custom fact
 * carries the same {@code ext-mem} address space and quoted evidence rules as
 * a pinned one.</p>
 */
public record Stm32CustomBoardProfile(
        String board,
        String exactPart,
        List<Stm32BoardProfile.ExternalRegion> externalRegions,
        List<Stm32BoardProfile.BootOffset> bootOffsets,
        Evidence confirmation) {

    private static final String SCHEMA = "urn:embedra:schema:stm32-custom-board-profile:1";

    private static final Set<String> ROOT_FIELDS = Set.of("$schema", "board", "exactPart",
        "confirmation", "externalRegions", "bootOffsets");

    private static final Set<String> REGION_FIELDS = Set.of("id", "kind", "controller", "device",
        "start", "size", "writable", "startEvidence", "sizeEvidence");

    private static final Set<String> BOOT_FIELDS = Set.of("id", "description", "offset");

    private static final Set<String> CONFIRMATION_FIELDS = Set.of("source", "detail");

    public Stm32CustomBoardProfile {
        Objects.requireNonNull(board, "board");
        Objects.requireNonNull(exactPart, "exactPart");
        Objects.requireNonNull(confirmation, "confirmation");
        externalRegions = List.copyOf(externalRegions);
        bootOffsets = List.copyOf(bootOffsets);
        if (board.isBlank() || exactPart.isBlank()) {
            throw new IllegalArgumentException("Custom profile identity is incomplete");
        }
        if (confirmation.kind() != EvidenceKind.USER_ASSERTION
                || confirmation.source().isBlank() || confirmation.detail().isBlank()) {
            throw new IllegalArgumentException(
                "A custom profile requires an explicit USER_ASSERTION confirmation");
        }
        if (externalRegions.isEmpty()) {
            throw new IllegalArgumentException("A custom profile requires an external region");
        }
        Set<String> ids = new java.util.HashSet<>();
        for (Stm32BoardProfile.ExternalRegion region : externalRegions) {
            if (!ids.add(region.id())) {
                throw new IllegalArgumentException("Duplicate custom external region id");
            }
        }
        for (int left = 0; left < externalRegions.size(); left++) {
            for (int right = left + 1; right < externalRegions.size(); right++) {
                if (externalRegions.get(left).range()
                        .overlaps(externalRegions.get(right).range())) {
                    throw new IllegalArgumentException("Overlapping custom external regions");
                }
            }
        }
    }

    /**
     * Loads one confirmed custom profile from a bounded user JSON file.
     *
     * @param path the user-supplied profile file; never a pinned snapshot
     * @param selection the digest-pinned curated selection the exact part must belong to
     * @param limits shared parser bounds
     * @param token cooperative cancellation
     * @return the validated immutable custom profile
     * @throws IOException when the file is missing, oversized, malformed, or
     *         names a part outside the curated selection
     * @throws DiagnosticException when the JSON structure is truncated or malformed
     */
    public static Stm32CustomBoardProfile load(Path path, Stm32PartSelection selection,
            ParserLimits limits, CancellationToken token)
            throws IOException, DiagnosticException {
        Objects.requireNonNull(path, "path");
        Objects.requireNonNull(selection, "selection");
        Objects.requireNonNull(limits, "limits");
        Objects.requireNonNull(token, "token");
        token.throwIfCancellationRequested();
        if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("Custom board profile path is not a regular file");
        }
        long size = Files.size(path);
        if (size > limits.maxInputBytes() || size > limits.maxAllocationBytes()) {
            throw new IOException("Custom board profile exceeds parser limits");
        }
        byte[] input = Files.readAllBytes(path);
        token.throwIfCancellationRequested();
        try {
            Map<?, ?> root = (Map<?, ?>) StrictJsonParser.parse(input, limits, token);
            if (!SCHEMA.equals(root.get("$schema"))) {
                throw new IOException("Custom board profile schema mismatch");
            }
            Map<String, Object> typed = typed(root);
            if (!typed.keySet().equals(ROOT_FIELDS)) {
                throw new IOException("Custom board profile root fields do not match schema");
            }
            String exactPart = string(typed, "exactPart");
            if (!selection.containsExactPart(exactPart)) {
                throw new IOException("Custom board profile is not a curated exact part: "
                    + exactPart);
            }
            Map<String, Object> confirmation = typedMap(typed.get("confirmation"),
                CONFIRMATION_FIELDS);
            List<Stm32BoardProfile.ExternalRegion> regions = new ArrayList<>();
            for (Object value : typedList(typed.get("externalRegions"))) {
                regions.add(region(typedMap(value, REGION_FIELDS)));
            }
            List<Stm32BoardProfile.BootOffset> boots = new ArrayList<>();
            for (Object value : typedList(typed.get("bootOffsets"))) {
                Map<String, Object> raw = typedMap(value, BOOT_FIELDS);
                boots.add(new Stm32BoardProfile.BootOffset(string(raw, "id"),
                    string(raw, "description"), longValue(raw, "offset")));
            }
            return new Stm32CustomBoardProfile(string(typed, "board"), exactPart, regions, boots,
                new Evidence(EvidenceKind.USER_ASSERTION, string(confirmation, "source"),
                    string(confirmation, "detail")));
        }
        catch (ClassCastException | NullPointerException | IllegalArgumentException exception) {
            throw new IOException("Custom board profile is invalid", exception);
        }
    }

    private static Stm32BoardProfile.ExternalRegion region(Map<String, Object> raw)
            throws IOException {
        Stm32BoardProfile.Kind kind;
        try {
            kind = Stm32BoardProfile.Kind.valueOf(string(raw, "kind"));
        }
        catch (IllegalArgumentException exception) {
            throw new IOException("Unknown custom external region kind");
        }
        Object writable = raw.get("writable");
        if (!(writable instanceof Boolean flag)) {
            throw new IOException("Custom external region writable flag must be boolean");
        }
        return new Stm32BoardProfile.ExternalRegion(string(raw, "id"), kind,
            string(raw, "controller"), string(raw, "device"),
            new AddressRange("ext-mem", longValue(raw, "start"), longValue(raw, "size")), flag,
            string(raw, "startEvidence"), string(raw, "sizeEvidence"));
    }

    private static long longValue(Map<String, Object> map, String key) throws IOException {
        Object value = map.get(key);
        if (!(value instanceof Long number)) {
            throw new IOException("Custom profile field must be an integer: " + key);
        }
        return number;
    }

    private static Map<String, Object> typedMap(Object value, Set<String> fields)
            throws IOException {
        if (!(value instanceof Map<?, ?> map)) {
            throw new IOException("Custom profile object is missing");
        }
        Map<String, Object> typed = typed(map);
        if (!typed.keySet().equals(fields)) {
            throw new IOException("Custom profile object fields do not match schema");
        }
        return typed;
    }

    private static Map<String, Object> typed(Map<?, ?> map) throws IOException {
        Map<String, Object> result = new LinkedHashMap<>();
        for (Map.Entry<?, ?> entry : map.entrySet()) {
            if (!(entry.getKey() instanceof String key)) {
                throw new IOException("Custom profile keys must be strings");
            }
            result.put(key, entry.getValue());
        }
        return result;
    }

    private static List<Object> typedList(Object value) throws IOException {
        if (!(value instanceof List<?> list)) {
            throw new IOException("Custom profile value must be an array");
        }
        return new ArrayList<>(list);
    }

    private static String string(Map<String, Object> map, String key) throws IOException {
        Object value = map.get(key);
        if (!(value instanceof String text)) {
            throw new IOException("Custom profile field must be a string: " + key);
        }
        return text;
    }
}
