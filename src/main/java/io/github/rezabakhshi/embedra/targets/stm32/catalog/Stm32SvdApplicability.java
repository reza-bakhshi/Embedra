package io.github.rezabakhshi.embedra.targets.stm32.catalog;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.core.stm32.input.Stm32PartSelection;
import io.github.rezabakhshi.embedra.pack.StrictJsonParser;
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
import java.util.TreeSet;

/**
 * Digest-pinned, reviewed exact-part SVD applicability for the curated selection.
 *
 * <p>An applicability entry is established only by an exact device-name prefix or a
 * named review override. Wildcard and neighbouring device lines never establish
 * applicability, and unresolved parts stay explicit with a reason and no data.</p>
 */
public final class Stm32SvdApplicability {
    public static final String SHA256 =
        "be795ab0d0d5da1b218428361690753fb39e8f962b3de8c160ae9a43d7970518";

    private static final String SCHEMA = "urn:embedra:schema:stm32-svd-applicability:1";

    private static final String SOURCE_REVISION =
        "e79021accd49bf19bd0b16065f5471fb073ff3ac";

    private static final Set<String> ROOT_FIELDS = Set.of("$schema", "curatedCatalogSha256",
        "svdRuleIndexSha256", "source", "selectionRule", "shippedDeviceLines", "parts");

    private static final Set<String> SOURCE_FIELDS = Set.of("identity", "url", "revision",
        "license", "redistribution");

    private static final Set<String> PART_FIELDS = Set.of("exactPart", "family", "status",
        "svdFiles", "reason");

    private static final Set<String> FILE_FIELDS = Set.of("deviceName", "path", "sha256", "cpu");

    public enum Status {
        EXACT_SVD_SHIPPED, EXACT_SVD_DEFERRED, UNAVAILABLE, AMBIGUOUS
    }

    public record SvdFile(String deviceName, String path, String sha256, String cpu) {
        public SvdFile {
            Objects.requireNonNull(deviceName, "deviceName");
            Objects.requireNonNull(path, "path");
            Objects.requireNonNull(sha256, "sha256");
            if (deviceName.isBlank() || deviceName.indexOf('X') >= 0
                || !deviceName.matches("[A-Z0-9_]+")) {
                throw new IllegalArgumentException("SVD device line is not exact");
            }
            if (path.isBlank() || path.startsWith("/") || path.contains("..")) {
                throw new IllegalArgumentException("SVD source path is unsafe");
            }
            if (!sha256.matches("[0-9a-f]{64}")) {
                throw new IllegalArgumentException("SVD source digest is not lowercase SHA-256");
            }
        }
    }

    public record Entry(String exactPart, String family, Status status,
            List<SvdFile> svdFiles, String reason) {
        public Entry {
            Objects.requireNonNull(exactPart, "exactPart");
            Objects.requireNonNull(family, "family");
            Objects.requireNonNull(status, "status");
            svdFiles = List.copyOf(svdFiles);
            boolean resolved = status == Status.EXACT_SVD_SHIPPED
                || status == Status.EXACT_SVD_DEFERRED;
            if (resolved && svdFiles.isEmpty()) {
                throw new IllegalArgumentException("Resolved applicability needs an SVD file");
            }
            if (!resolved && (!svdFiles.isEmpty() || reason == null || reason.isBlank())) {
                throw new IllegalArgumentException(
                    "Unresolved applicability must stay explicit with a reason");
            }
        }
    }

    private final Map<String, Entry> entries;

    private final List<String> shippedDeviceLines;

    private Stm32SvdApplicability(Map<String, Entry> entries, List<String> shippedDeviceLines) {
        this.entries = Map.copyOf(entries);
        this.shippedDeviceLines = List.copyOf(shippedDeviceLines);
    }

    public static Stm32SvdApplicability load(Path path, Stm32PartSelection selection,
            ParserLimits limits, CancellationToken token)
            throws IOException, DiagnosticException {
        Objects.requireNonNull(path, "path");
        Objects.requireNonNull(selection, "selection");
        Objects.requireNonNull(limits, "limits");
        Objects.requireNonNull(token, "token");
        token.throwIfCancellationRequested();
        if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("STM32 SVD applicability path is not a regular file");
        }
        long size = Files.size(path);
        if (size > limits.maxInputBytes() || size > limits.maxAllocationBytes()) {
            throw new IOException("STM32 SVD applicability exceeds parser limits");
        }
        byte[] input = Files.readAllBytes(path);
        token.throwIfCancellationRequested();
        if (!SHA256.equals(sha256(input))) {
            throw new IOException("STM32 SVD applicability digest mismatch");
        }
        try {
            Map<?, ?> root = (Map<?, ?>) StrictJsonParser.parse(input, limits, token);
            if (!SCHEMA.equals(root.get("$schema"))
                || root.keySet().stream().anyMatch(key -> !(key instanceof String))) {
                throw new IOException("STM32 SVD applicability schema mismatch");
            }
            Map<String, Object> typed = typed(root);
            if (!typed.keySet().equals(ROOT_FIELDS)) {
                throw new IOException("STM32 SVD applicability fields do not match schema");
            }
            Map<String, Object> source = typedMap(typed.get("source"), SOURCE_FIELDS);
            if (!SOURCE_REVISION.equals(source.get("revision"))) {
                throw new IOException("STM32 SVD applicability source revision mismatch");
            }
            Map<String, Entry> entries = new LinkedHashMap<>();
            for (Object value : typedList(typed.get("parts"))) {
                Entry entry = entry(typedMap(value, PART_FIELDS));
                if (!selection.containsExactPart(entry.exactPart())
                    || entries.putIfAbsent(entry.exactPart(), entry) != null) {
                    throw new IOException(
                        "Unknown or duplicate applicability exact part");
                }
            }
            List<String> shipped = new ArrayList<>();
            for (Object value : typedList(typed.get("shippedDeviceLines"))) {
                if (!(value instanceof String text)) {
                    throw new IOException("Shipped device line must be a string");
                }
                shipped.add(text);
            }
            return new Stm32SvdApplicability(entries, shipped);
        }
        catch (ClassCastException | NullPointerException | IllegalArgumentException exception) {
            throw new IOException("STM32 SVD applicability is invalid", exception);
        }
    }

    public List<Entry> entries() {
        return entries.values().stream()
            .sorted(Comparator.comparing(Entry::exactPart)).toList();
    }

    public int size() {
        return entries.size();
    }

    public Entry requireEntry(String exactPart) {
        Entry entry = entries.get(exactPart);
        if (entry == null) {
            throw new IllegalArgumentException("Unknown curated exact part: " + exactPart);
        }
        return entry;
    }

    public List<String> shippedDeviceLines() {
        return shippedDeviceLines;
    }

    public Set<String> families() {
        Set<String> families = new TreeSet<>();
        entries.values().forEach(entry -> families.add(entry.family()));
        return Set.copyOf(families);
    }

    private static Entry entry(Map<String, Object> value) throws IOException {
        String exactPart = string(value, "exactPart");
        String family = string(value, "family");
        Status status;
        try {
            status = Status.valueOf(string(value, "status"));
        }
        catch (IllegalArgumentException exception) {
            throw new IOException("Unknown applicability status");
        }
        List<SvdFile> files = new ArrayList<>();
        for (Object object : typedList(value.get("svdFiles"))) {
            Map<String, Object> file = typedMap(object, FILE_FIELDS);
            files.add(new SvdFile(string(file, "deviceName"), string(file, "path"),
                string(file, "sha256"), nullableString(file.get("cpu"))));
        }
        Object reasonValue = value.get("reason");
        if (reasonValue != null && !(reasonValue instanceof String)) {
            throw new IOException("Applicability reason must be a string or null");
        }
        return new Entry(exactPart, family, status, files, (String) reasonValue);
    }

    private static Map<String, Object> typedMap(Object value, Set<String> fields)
            throws IOException {
        if (!(value instanceof Map<?, ?> map)) {
            throw new IOException("Applicability object is missing");
        }
        Map<String, Object> typed = typed(map);
        if (!typed.keySet().equals(fields)) {
            throw new IOException("Applicability object fields do not match schema");
        }
        return typed;
    }

    private static Map<String, Object> typed(Map<?, ?> map) throws IOException {
        Map<String, Object> result = new LinkedHashMap<>();
        for (Map.Entry<?, ?> entry : map.entrySet()) {
            if (!(entry.getKey() instanceof String key)) {
                throw new IOException("Applicability keys must be strings");
            }
            result.put(key, entry.getValue());
        }
        return result;
    }

    private static List<Object> typedList(Object value) throws IOException {
        if (!(value instanceof List<?> list)) {
            throw new IOException("Applicability value must be an array");
        }
        return new ArrayList<>(list);
    }

    private static String string(Map<String, Object> map, String key) throws IOException {
        Object value = map.get(key);
        if (!(value instanceof String text)) {
            throw new IOException("Applicability field must be a string: " + key);
        }
        return text;
    }

    private static String nullableString(Object value) throws IOException {
        if (value == null) {
            return null;
        }
        if (!(value instanceof String text)) {
            throw new IOException("Applicability field must be a string or null");
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
