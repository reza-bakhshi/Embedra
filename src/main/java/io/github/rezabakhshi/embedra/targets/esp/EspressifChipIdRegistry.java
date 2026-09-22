package io.github.rezabakhshi.embedra.targets.esp;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/** Immutable registry loaded from maintained, provenance-bearing chip-ID data. */
public final class EspressifChipIdRegistry {
    private static final String BUNDLED_RESOURCE =
        "/io/github/rezabakhshi/embedra/targets/esp/espressif-chip-ids.tsv";

    private final Map<Integer, EspressifChipDefinition> byChipId;

    private EspressifChipIdRegistry(Map<Integer, EspressifChipDefinition> definitions) {
        byChipId = Map.copyOf(definitions);
    }

    public static EspressifChipIdRegistry loadBundled() {
        try (InputStream input = EspressifChipIdRegistry.class.getResourceAsStream(
                BUNDLED_RESOURCE)) {
            if (input == null) {
                throw new IllegalStateException("Bundled Espressif chip-ID registry is missing");
            }
            return parse(input);
        }
        catch (IOException exception) {
            throw new IllegalStateException("Cannot read bundled Espressif chip-ID registry",
                exception);
        }
    }

    static EspressifChipIdRegistry parse(InputStream input) throws IOException {
        Objects.requireNonNull(input, "input");
        Map<Integer, EspressifChipDefinition> definitions = new LinkedHashMap<>();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(input,
                StandardCharsets.UTF_8))) {
            String line;
            int lineNumber = 0;
            while ((line = reader.readLine()) != null) {
                lineNumber++;
                if (line.isBlank() || line.startsWith("#")) {
                    continue;
                }
                String[] fields = line.split("\\t", -1);
                if (fields.length != 6) {
                    throw new IOException("Invalid chip-ID registry row at line " + lineNumber);
                }
                int chipId;
                try {
                    chipId = Integer.parseUnsignedInt(fields[0]);
                }
                catch (NumberFormatException exception) {
                    throw new IOException("Invalid chip ID at line " + lineNumber, exception);
                }
                EspressifChipDefinition definition = new EspressifChipDefinition(chipId,
                    fields[1], fields[2], fields[3], fields[4], fields[5]);
                if (definitions.putIfAbsent(chipId, definition) != null) {
                    throw new IOException("Duplicate chip ID at line " + lineNumber);
                }
            }
        }
        if (definitions.isEmpty()) {
            throw new IOException("Espressif chip-ID registry is empty");
        }
        return new EspressifChipIdRegistry(definitions);
    }

    public Optional<EspressifChipDefinition> findByChipId(int chipId) {
        return Optional.ofNullable(byChipId.get(chipId));
    }

    public EspressifChipDefinition requireByChipId(int chipId) {
        return findByChipId(chipId).orElseThrow(() ->
            new IllegalArgumentException("Unknown Espressif chip ID: " + chipId));
    }
}
