package io.github.rezabakhshi.embedra.targets.stm32.catalog;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
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
import java.util.Collections;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.OptionalInt;
import java.util.Set;
import java.util.TreeSet;

/** Digest-checked catalog descriptors; device memory and SVD packs follow later tasks. */
public final class Stm32DevicePackRegistry implements Stm32PartSelection {
    public static final String CATALOG_SHA256 =
        "afc66a47cd79c2025d115049c8aebd2db671c1112d42531b1db50df8514858f9";

    private static final String SCHEMA = "urn:embedra:schema:stm32-curated-catalog:1";

    public record Processor(String core, int index, String role) {
    }

    public enum SearchStatus {
        NO_MATCH, SINGLE_CANDIDATE, AMBIGUOUS, EXACT_ID
    }

    public record SearchResult(SearchStatus status, List<Part> candidates) {
        public SearchResult {
            candidates = List.copyOf(candidates);
        }
    }

    public record Part(String exactPart, String family, String line, String packageName,
            OptionalInt flashKiB, List<Integer> flashCandidatesKiB, OptionalInt ramKiB,
            List<Processor> processors, String lifecycle, String supportState,
            String marketingStatus, String referencePattern, String sourceReferenceSha256,
            String catalogSha256) {
        public Part {
            flashCandidatesKiB = List.copyOf(flashCandidatesKiB);
            processors = List.copyOf(processors);
        }

        public List<String> cores() {
            return processors.stream().map(Processor::core).toList();
        }

        /** No device map, SVD, or interrupt pack is registered by catalog membership. */
        public String packStatus() {
            return "CATALOG_ONLY";
        }
    }

    private final Map<String, Part> parts;

    private Stm32DevicePackRegistry(Map<String, Part> parts) {
        this.parts = Map.copyOf(parts);
    }

    public static Stm32DevicePackRegistry load(Path catalogPath,
            Stm32PartSelection selection, ParserLimits limits,
            CancellationToken cancellation) throws IOException, DiagnosticException {
        Objects.requireNonNull(catalogPath, "catalogPath");
        Objects.requireNonNull(selection, "selection");
        Objects.requireNonNull(limits, "limits");
        Objects.requireNonNull(cancellation, "cancellation");
        cancellation.throwIfCancellationRequested();
        if (!(selection instanceof Stm32CuratedPartIds ids) || ids.size() != 53) {
            throw new IOException("Registry requires the pinned exact-part selection");
        }
        if (!Files.isRegularFile(catalogPath, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("Curated STM32 catalog path is not a regular file");
        }
        long length = Files.size(catalogPath);
        if (length > limits.maxInputBytes() || length > limits.maxAllocationBytes()) {
            throw new IOException("Curated STM32 catalog exceeds parser limits");
        }
        byte[] input = Files.readAllBytes(catalogPath);
        cancellation.throwIfCancellationRequested();
        if (!CATALOG_SHA256.equals(sha256(input))) {
            throw new IOException("Curated STM32 catalog digest mismatch");
        }
        try {
            Map<?, ?> root = (Map<?, ?>) StrictJsonParser.parse(input, limits, cancellation);
            if (!SCHEMA.equals(root.get("$schema")) || !Stm32CuratedPartIds.SELECTION_SHA256
                    .equals(root.get("selectionSha256"))) {
                throw new IOException("Catalog schema or selected-parts digest mismatch");
            }
            List<?> records = (List<?>) root.get("records");
            if (records.size() != ids.size()) {
                throw new IOException("Curated catalog does not cover the selected parts");
            }
            Map<String, Part> parsed = new LinkedHashMap<>();
            for (Object object : records) {
                cancellation.throwIfCancellationRequested();
                Part part = parsePart((Map<?, ?>) object);
                if (!ids.containsExactPart(part.exactPart())
                        || parsed.putIfAbsent(part.exactPart(), part) != null) {
                    throw new IOException("Unknown or duplicate exact part in curated catalog");
                }
            }
            return new Stm32DevicePackRegistry(parsed);
        }
        catch (ClassCastException | NullPointerException | IllegalArgumentException exception) {
            throw new IOException("Curated STM32 catalog has invalid identity fields", exception);
        }
    }

    public List<Part> parts() {
        return parts.values().stream().sorted(Comparator.comparing(Part::exactPart)).toList();
    }

    public int size() {
        return parts.size();
    }

    public Set<String> families() {
        Set<String> families = new TreeSet<>();
        parts.values().forEach(part -> families.add(part.family()));
        return Collections.unmodifiableSet(families);
    }

    /** Search is case-insensitive but returns candidates, never an implicit selection. */
    public List<Part> search(String query) {
        Objects.requireNonNull(query, "query");
        String needle = query.trim().toUpperCase(Locale.ROOT);
        if (needle.isEmpty()) {
            return List.of();
        }
        return parts().stream().filter(part -> part.exactPart().contains(needle)
            || part.family().contains(needle) || part.line().contains(needle)).toList();
    }

    /** A unique partial match is still only a suggestion until its exact ID is selected. */
    public SearchResult resolve(String query) {
        Objects.requireNonNull(query, "query");
        Part exact = parts.get(query);
        if (exact != null) {
            return new SearchResult(SearchStatus.EXACT_ID, List.of(exact));
        }
        List<Part> candidates = search(query);
        SearchStatus status;
        if (candidates.isEmpty()) {
            status = SearchStatus.NO_MATCH;
        }
        else if (candidates.size() > 1) {
            status = SearchStatus.AMBIGUOUS;
        }
        else {
            status = SearchStatus.SINGLE_CANDIDATE;
        }
        return new SearchResult(status, candidates);
    }

    public Part selectExact(String exactPart) {
        Objects.requireNonNull(exactPart, "exactPart");
        Part part = parts.get(exactPart);
        if (part == null) {
            throw new IllegalArgumentException("Select an exact curated STM32 part ID");
        }
        return part;
    }

    @Override
    public boolean containsExactPart(String exactPart) {
        return parts.containsKey(exactPart);
    }

    private static Part parsePart(Map<?, ?> source) throws IOException {
        String exactPart = (String) source.get("exactPart");
        String support = (String) source.get("supportState");
        if (!"EXACT_ORDERABLE_PART".equals(source.get("identityKind"))
                || !"PLANNED".equals(support)) {
            throw new IOException("Catalog records must remain exact and planned");
        }
        List<Processor> processors = new ArrayList<>();
        for (Object object : (List<?>) source.get("processors")) {
            Map<?, ?> processor = (Map<?, ?>) object;
            processors.add(new Processor((String) processor.get("core"),
                Math.toIntExact((Long) processor.get("index")),
                (String) processor.get("role")));
        }
        if (exactPart == null || processors.isEmpty()) {
            throw new IOException("Catalog record has no exact part or processor");
        }
        List<Integer> flashCandidates = ((List<?>) source.get("flashKiBCandidates"))
            .stream().map(value -> Math.toIntExact((Long) value)).toList();
        return new Part(exactPart, (String) source.get("family"),
            (String) source.get("line"), (String) source.get("package"),
            optionalInt(source.get("flashKiB")), flashCandidates,
            optionalInt(source.get("ramKiB")), processors,
            (String) source.get("lifecycle"), support,
            (String) source.get("marketingStatusOnSelectionDate"),
            (String) source.get("referencePattern"),
            (String) source.get("sourceReferenceSha256"), CATALOG_SHA256);
    }

    private static OptionalInt optionalInt(Object value) {
        return value == null ? OptionalInt.empty() :
            OptionalInt.of(Math.toIntExact((Long) value));
    }

    private static String sha256(byte[] input) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(input));
        }
        catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 unavailable", exception);
        }
    }
}
