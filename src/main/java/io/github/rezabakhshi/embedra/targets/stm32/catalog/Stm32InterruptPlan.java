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
import java.util.Comparator;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Exact-part CMSIS interrupt data from the digest-pinned curated catalog.
 *
 * <p>Only parts whose interrupt header mapping is a single exact header expose an
 * applicable interrupt set. Variant or conditional mappings remain explicit and
 * apply nothing.</p>
 */
public final class Stm32InterruptPlan {
    public static final String APPLICABLE = "MAPPED_SINGLE";

    private final Map<String, Entry> entries;

    private Stm32InterruptPlan(Map<String, Entry> entries) {
        this.entries = Map.copyOf(entries);
    }

    public record Interrupt(String name, int number) {
        public Interrupt {
            Objects.requireNonNull(name, "name");
            if (name.isBlank() || number < -16 || number > 65535) {
                throw new IllegalArgumentException("Interrupt definition is invalid");
            }
        }
    }

    public record Entry(String exactPart, String status, String header,
            List<Interrupt> interrupts) {
        public Entry {
            Objects.requireNonNull(exactPart, "exactPart");
            Objects.requireNonNull(status, "status");
            interrupts = List.copyOf(interrupts);
        }

        /** Interrupts may be applied only when the mapping is a single exact header. */
        public boolean applicable() {
            return APPLICABLE.equals(status) && !interrupts.isEmpty();
        }
    }

    public static Stm32InterruptPlan load(Path catalogPath, Stm32PartSelection selection,
            ParserLimits limits, CancellationToken token)
            throws IOException, DiagnosticException {
        Objects.requireNonNull(catalogPath, "catalogPath");
        Objects.requireNonNull(selection, "selection");
        Objects.requireNonNull(limits, "limits");
        Objects.requireNonNull(token, "token");
        token.throwIfCancellationRequested();
        if (!Files.isRegularFile(catalogPath, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("Curated STM32 catalog path is not a regular file");
        }
        long size = Files.size(catalogPath);
        if (size > limits.maxInputBytes() || size > limits.maxAllocationBytes()) {
            throw new IOException("Curated STM32 catalog exceeds parser limits");
        }
        byte[] input = Files.readAllBytes(catalogPath);
        token.throwIfCancellationRequested();
        if (!Stm32DevicePackRegistry.CATALOG_SHA256.equals(sha256(input))) {
            throw new IOException("Curated STM32 catalog digest mismatch");
        }
        try {
            Map<?, ?> root = (Map<?, ?>) StrictJsonParser.parse(input, limits, token);
            List<?> records = (List<?>) root.get("records");
            Map<String, Entry> entries = new LinkedHashMap<>();
            for (Object object : records) {
                token.throwIfCancellationRequested();
                Map<?, ?> record = (Map<?, ?>) object;
                String exactPart = (String) record.get("exactPart");
                String status = (String) record.get("interruptStatus");
                String header = (String) record.get("interruptHeader");
                List<Interrupt> interrupts = new ArrayList<>();
                Set<String> interruptNames = new HashSet<>();
                for (Object item : (List<?>) record.get("interrupts")) {
                    String name = (String) ((Map<?, ?>) item).get("name");
                    long number = (Long) ((Map<?, ?>) item).get("number");
                    if (!interruptNames.add(name)) {
                        throw new IOException("Duplicate interrupt name in one exact part");
                    }
                    interrupts.add(new Interrupt(name, Math.toIntExact(number)));
                }
                if (exactPart == null || status == null
                    || !selection.containsExactPart(exactPart)
                    || entries.putIfAbsent(exactPart, new Entry(exactPart, status, header,
                        interrupts)) != null) {
                    throw new IOException("Invalid or duplicate interrupt record");
                }
            }
            return new Stm32InterruptPlan(entries);
        }
        catch (ClassCastException | NullPointerException | IllegalArgumentException
                | ArithmeticException exception) {
            throw new IOException("Curated STM32 interrupt data is invalid", exception);
        }
    }

    public List<Entry> entries() {
        return entries.values().stream()
            .sorted(Comparator.comparing(Entry::exactPart)).toList();
    }

    public Entry requireEntry(String exactPart) {
        Entry entry = entries.get(exactPart);
        if (entry == null) {
            throw new IllegalArgumentException("Unknown curated exact part: " + exactPart);
        }
        return entry;
    }

    public int size() {
        return entries.size();
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
