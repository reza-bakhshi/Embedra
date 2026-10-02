package io.github.rezabakhshi.embedra.targets.stm32.security;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.core.io.AddressRange;
import io.github.rezabakhshi.embedra.core.stm32.input.Stm32PartSelection;
import io.github.rezabakhshi.embedra.pack.StrictJsonParser;
import io.github.rezabakhshi.embedra.targets.stm32.catalog.Stm32CuratedPartIds;
import io.github.rezabakhshi.embedra.targets.stm32.catalog.Stm32DevicePackRegistry;
import io.github.rezabakhshi.embedra.targets.stm32.memory.Stm32MemoryPlanner;
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
 * Digest-pinned, reviewed STM32 TrustZone security-domain snapshot.
 *
 * <p>Loading verifies the exact snapshot digest, the pinned curated selection,
 * header-evidence, interrupt-index, and memory-plan digests, every record's
 * closed schema, exact-part membership, duplicate records, and the recorded
 * alias/unavailable counts before exposing records. A part with no pinned
 * evidence stays explicit with a reason and no window.</p>
 */
public final class Stm32SecurityCatalog {
    /** SHA-256 of the shipped security-domain snapshot. */
    public static final String SHA256 =
        "08da45f506d670df3ed042243513d0a3751d07cce2b256cb2c46cd7db23ee3e9";

    /** SHA-256 of the pinned T039 header evidence used for alias symbols. */
    public static final String HEADER_EVIDENCE_SHA256 =
        "491c148f623de7ac3e14f2c1e99ec919b3223afda470d57de3040405ed07a4a5";

    /** SHA-256 of the pinned CMSIS interrupt index used for SecureFault evidence. */
    public static final String INTERRUPT_INDEX_SHA256 =
        "2c312786d907f85babde522944141d0672094749e787ce87078c14bc07495f72";

    private static final String SCHEMA = "urn:embedra:schema:stm32-security-domains:1";

    private static final Set<String> ROOT_FIELDS = Set.of("$schema", "curatedCatalogSha256",
        "selectionSha256", "cmsisHeaderEvidenceSha256", "cmsisInterruptIndexSha256",
        "memoryPlansSha256", "aliasViewParts", "unavailableParts", "records");

    private static final Set<String> RECORD_FIELDS = Set.of("exactPart", "status", "reason",
        "sourceHeaders", "windows", "unresolvedAliasSymbols", "nonSecureCallable",
        "veneerEvidence");

    private static final Set<String> HEADER_FIELDS = Set.of("repository", "commit", "path",
        "sha256", "license");

    private static final Set<String> WINDOW_FIELDS = Set.of("id", "kind", "attribute",
        "boundaryKind", "start", "size", "pairedRegionId", "pairedAliasIds", "baseSymbol",
        "baseLine", "baseDeclaration", "headerPath", "partitionState");

    private static final Set<String> UNRESOLVED_FIELDS = Set.of("symbol", "reason");

    private static final Set<String> NSC_FIELDS = Set.of("status", "reason",
        "configurationEvidence");

    private static final Set<String> VENEER_FIELDS = Set.of("status", "reason",
        "secureFaultException", "transitions");

    private static final Set<String> FAULT_FIELDS = Set.of("name", "number");

    private static final Set<String> TRANSITION_FIELDS = Set.of("id", "start", "size",
        "targetRegionId", "evidenceId");

    private final List<Stm32SecurityRecord> records;

    private final int aliasViewParts;

    private final int unavailableParts;

    private Stm32SecurityCatalog(List<Stm32SecurityRecord> records, int aliasViewParts,
            int unavailableParts) {
        this.records = List.copyOf(records);
        this.aliasViewParts = aliasViewParts;
        this.unavailableParts = unavailableParts;
    }

    public static Stm32SecurityCatalog load(Path path, Stm32PartSelection selection,
            ParserLimits limits, CancellationToken token)
            throws IOException, DiagnosticException {
        Objects.requireNonNull(path, "path");
        Objects.requireNonNull(selection, "selection");
        Objects.requireNonNull(limits, "limits");
        Objects.requireNonNull(token, "token");
        token.throwIfCancellationRequested();
        if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("STM32 security-domain path is not a regular file");
        }
        long size = Files.size(path);
        if (size > limits.maxInputBytes() || size > limits.maxAllocationBytes()) {
            throw new IOException("STM32 security domains exceed parser limits");
        }
        byte[] input = Files.readAllBytes(path);
        token.throwIfCancellationRequested();
        return parse(input, SHA256, selection, limits, token);
    }

    static Stm32SecurityCatalog parse(byte[] input, String expectedSha256,
            Stm32PartSelection selection, ParserLimits limits, CancellationToken token)
            throws IOException, DiagnosticException {
        Objects.requireNonNull(input, "input");
        Objects.requireNonNull(expectedSha256, "expectedSha256");
        if (input.length > limits.maxAllocationBytes()) {
            throw new IOException("STM32 security domains exceed allocation limits");
        }
        if (!expectedSha256.equals(sha256(input))) {
            throw new IOException("STM32 security-domain digest mismatch");
        }
        token.throwIfCancellationRequested();
        try {
            Map<?, ?> root = (Map<?, ?>) StrictJsonParser.parse(input, limits, token);
            if (!SCHEMA.equals(root.get("$schema"))) {
                throw new IOException("STM32 security-domain schema mismatch");
            }
            Map<String, Object> typed = typed(root);
            if (!typed.keySet().equals(ROOT_FIELDS)
                    || !Stm32CuratedPartIds.SELECTION_SHA256
                        .equals(typed.get("selectionSha256"))
                    || !Stm32DevicePackRegistry.CATALOG_SHA256
                        .equals(typed.get("curatedCatalogSha256"))
                    || !HEADER_EVIDENCE_SHA256
                        .equals(typed.get("cmsisHeaderEvidenceSha256"))
                    || !INTERRUPT_INDEX_SHA256
                        .equals(typed.get("cmsisInterruptIndexSha256"))
                    || !Stm32MemoryPlanner.CATALOG_SHA256
                        .equals(typed.get("memoryPlansSha256"))) {
                throw new IOException("STM32 security-domain root fields or pins mismatch");
            }
            List<Stm32SecurityRecord> records = new ArrayList<>();
            Map<String, Stm32SecurityRecord> byPart = new LinkedHashMap<>();
            int alias = 0;
            for (Object value : typedList(typed.get("records"))) {
                token.throwIfCancellationRequested();
                Stm32SecurityRecord record =
                    record(typedMap(value, RECORD_FIELDS), selection);
                if (byPart.putIfAbsent(record.exactPart(), record) != null) {
                    throw new IOException("Duplicate security record for "
                        + record.exactPart());
                }
                if (record.pinned()) {
                    alias++;
                }
                records.add(record);
            }
            int unavailable = records.size() - alias;
            if (longValue(typed, "aliasViewParts") != alias
                    || longValue(typed, "unavailableParts") != unavailable) {
                throw new IOException("Security-domain recorded counts mismatch");
            }
            return new Stm32SecurityCatalog(records, alias, unavailable);
        }
        catch (ClassCastException | NullPointerException | IllegalArgumentException exception) {
            throw new IOException("STM32 security domains are invalid", exception);
        }
    }

    public List<Stm32SecurityRecord> records() {
        return records.stream()
            .sorted(Comparator.comparing(Stm32SecurityRecord::exactPart))
            .toList();
    }

    public int size() {
        return records.size();
    }

    public int aliasViewParts() {
        return aliasViewParts;
    }

    public int unavailableParts() {
        return unavailableParts;
    }

    /** The single record for an exact part, or an explicit failure. */
    public Stm32SecurityRecord requireRecord(String exactPart) {
        Objects.requireNonNull(exactPart, "exactPart");
        return records.stream().filter(record -> record.exactPart().equals(exactPart))
            .findFirst()
            .orElseThrow(() -> new IllegalArgumentException(
                "No security-domain record for " + exactPart));
    }

    private static Stm32SecurityRecord record(Map<String, Object> value,
            Stm32PartSelection selection) throws IOException {
        String exactPart = string(value, "exactPart");
        if (!selection.containsExactPart(exactPart)) {
            throw new IOException("Security record is not a curated exact part: " + exactPart);
        }
        Stm32SecurityRecord.Status status;
        try {
            status = Stm32SecurityRecord.Status.valueOf(string(value, "status"));
        }
        catch (IllegalArgumentException exception) {
            throw new IOException("Unknown security record status");
        }
        List<Stm32SecurityHeaderSource> headers = new ArrayList<>();
        for (Object object : typedList(value.get("sourceHeaders"))) {
            Map<String, Object> raw = typedMap(object, HEADER_FIELDS);
            headers.add(new Stm32SecurityHeaderSource(string(raw, "repository"),
                string(raw, "commit"), string(raw, "path"), string(raw, "sha256"),
                string(raw, "license")));
        }
        List<Stm32SecurityWindow> windows = new ArrayList<>();
        for (Object object : typedList(value.get("windows"))) {
            windows.add(window(typedMap(object, WINDOW_FIELDS)));
        }
        List<Stm32SecurityRecord.UnresolvedAlias> unresolved = new ArrayList<>();
        for (Object object : typedList(value.get("unresolvedAliasSymbols"))) {
            Map<String, Object> raw = typedMap(object, UNRESOLVED_FIELDS);
            unresolved.add(new Stm32SecurityRecord.UnresolvedAlias(
                string(raw, "symbol"), string(raw, "reason")));
        }
        return new Stm32SecurityRecord(exactPart, status,
            nullableString(value.get("reason")), headers, windows, unresolved,
            nsc(typedMap(value.get("nonSecureCallable"), NSC_FIELDS)),
            veneer(typedMap(value.get("veneerEvidence"), VENEER_FIELDS)));
    }

    private static Stm32SecurityWindow window(Map<String, Object> value) throws IOException {
        Stm32SecurityWindow.Kind kind;
        Stm32SecurityAttribute attribute;
        Stm32SecurityWindow.BoundaryKind boundaryKind;
        Stm32SecurityWindow.PartitionState partitionState;
        try {
            kind = Stm32SecurityWindow.Kind.valueOf(string(value, "kind"));
            attribute = Stm32SecurityAttribute.valueOf(string(value, "attribute"));
            boundaryKind =
                Stm32SecurityWindow.BoundaryKind.valueOf(string(value, "boundaryKind"));
            partitionState =
                Stm32SecurityWindow.PartitionState.valueOf(string(value, "partitionState"));
        }
        catch (IllegalArgumentException exception) {
            throw new IOException("Unknown security window value");
        }
        List<String> aliases = new ArrayList<>();
        for (Object object : typedList(value.get("pairedAliasIds"))) {
            if (!(object instanceof String alias)) {
                throw new IOException("Security window alias ids must be strings");
            }
            aliases.add(alias);
        }
        return new Stm32SecurityWindow(string(value, "id"), kind, attribute, boundaryKind,
            longValue(value, "start"), longValue(value, "size"),
            string(value, "pairedRegionId"), aliases, string(value, "baseSymbol"),
            Math.toIntExact(longValue(value, "baseLine")), string(value, "baseDeclaration"),
            string(value, "headerPath"), partitionState);
    }

    private static Stm32SecurityRecord.NscBoundary nsc(Map<String, Object> value)
            throws IOException {
        Stm32SecurityRecord.EvidenceState status;
        try {
            status = Stm32SecurityRecord.EvidenceState.valueOf(string(value, "status"));
        }
        catch (IllegalArgumentException exception) {
            throw new IOException("Unknown NSC boundary status");
        }
        List<String> evidence = new ArrayList<>();
        for (Object object : typedList(value.get("configurationEvidence"))) {
            if (!(object instanceof String symbol)) {
                throw new IOException("NSC configuration evidence must be strings");
            }
            evidence.add(symbol);
        }
        return new Stm32SecurityRecord.NscBoundary(status, string(value, "reason"), evidence);
    }

    private static Stm32SecurityRecord.VeneerEvidence veneer(Map<String, Object> value)
            throws IOException {
        Stm32SecurityRecord.EvidenceState status;
        try {
            status = Stm32SecurityRecord.EvidenceState.valueOf(string(value, "status"));
        }
        catch (IllegalArgumentException exception) {
            throw new IOException("Unknown veneer evidence status");
        }
        Stm32SecurityRecord.SecureFaultException fault = null;
        if (value.get("secureFaultException") != null) {
            Map<String, Object> raw =
                typedMap(value.get("secureFaultException"), FAULT_FIELDS);
            fault = new Stm32SecurityRecord.SecureFaultException(string(raw, "name"),
                Math.toIntExact(longValue(raw, "number")));
        }
        List<Stm32VeneerTransition> transitions = new ArrayList<>();
        for (Object object : typedList(value.get("transitions"))) {
            Map<String, Object> raw = typedMap(object, TRANSITION_FIELDS);
            transitions.add(new Stm32VeneerTransition(string(raw, "id"),
                new AddressRange(Stm32SecurityWindow.ADDRESS_SPACE, longValue(raw, "start"),
                    longValue(raw, "size")),
                string(raw, "targetRegionId"), string(raw, "evidenceId")));
        }
        return new Stm32SecurityRecord.VeneerEvidence(status, string(value, "reason"), fault,
            transitions);
    }

    private static long longValue(Map<String, Object> map, String key) throws IOException {
        Object value = map.get(key);
        if (!(value instanceof Long number)) {
            throw new IOException("Security-domain field must be an integer: " + key);
        }
        return number;
    }

    private static Map<String, Object> typedMap(Object value, Set<String> fields)
            throws IOException {
        if (!(value instanceof Map<?, ?> map)) {
            throw new IOException("Security-domain object is missing");
        }
        Map<String, Object> typed = typed(map);
        if (!typed.keySet().equals(fields)) {
            throw new IOException("Security-domain object fields do not match schema");
        }
        return typed;
    }

    private static Map<String, Object> typed(Map<?, ?> map) throws IOException {
        Map<String, Object> result = new LinkedHashMap<>();
        for (Map.Entry<?, ?> entry : map.entrySet()) {
            if (!(entry.getKey() instanceof String key)) {
                throw new IOException("Security-domain keys must be strings");
            }
            result.put(key, entry.getValue());
        }
        return result;
    }

    private static List<Object> typedList(Object value) throws IOException {
        if (!(value instanceof List<?> list)) {
            throw new IOException("Security-domain value must be an array");
        }
        return new ArrayList<>(list);
    }

    private static String string(Map<String, Object> map, String key) throws IOException {
        Object value = map.get(key);
        if (!(value instanceof String text)) {
            throw new IOException("Security-domain field must be a string: " + key);
        }
        return text;
    }

    private static String nullableString(Object value) throws IOException {
        if (value == null) {
            return null;
        }
        if (!(value instanceof String text)) {
            throw new IOException("Security-domain field must be a string or null");
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
