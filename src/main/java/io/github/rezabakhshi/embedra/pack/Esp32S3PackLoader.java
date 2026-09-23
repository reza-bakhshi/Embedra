package io.github.rezabakhshi.embedra.pack;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Integrity-first loader for the generated ESP32-S3 enrichment packs. */
public final class Esp32S3PackLoader {
    private static final String DEVICE_ID = "esp32s3";

    private static final String ROM_PACK_ID = "espressif.esp32s3.rom";

    private static final String PERIPHERAL_PACK_ID = "espressif.esp32s3.peripherals";

    private static final String ROM_SCHEMA = "urn:embedra:schema:esp-rom-symbol-pack:1";

    private static final String PERIPHERAL_SCHEMA =
        "urn:embedra:schema:esp-peripheral-pack:1";

    private Esp32S3PackLoader() {
    }

    public static EspRomSymbolPack loadRom(Path directory, ParserLimits limits,
            CancellationToken cancellation) throws DiagnosticException {
        LoadedContent loaded = loadVerified(directory, ROM_PACK_ID,
            "rom-symbols.json", limits, cancellation);
        Map<String, Object> root = object(StrictJsonParser.parse(loaded.bytes(), limits,
            cancellation), "ROM pack root must be an object");
        exact(root, Set.of("schemaId", "deviceId", "sourceRevision", "sourceFiles",
            "symbols"));
        requireIdentity(root, ROM_SCHEMA, loaded.manifest());
        List<EspRomSymbol> symbols = new ArrayList<>();
        for (Object value : array(root.get("symbols"), "ROM symbols must be an array")) {
            cancellation.throwIfCancellationRequested();
            Map<String, Object> symbol = object(value, "ROM symbol must be an object");
            exact(symbol, Set.of("name", "address", "kind", "sourceFiles"));
            try {
                symbols.add(new EspRomSymbol(string(symbol, "name"),
                    integer(symbol, "address"),
                    EspRomSymbolKind.valueOf(string(symbol, "kind")),
                    strings(symbol.get("sourceFiles"), "ROM symbol sources")));
            }
            catch (IllegalArgumentException | NullPointerException exception) {
                throw invalid("Invalid ROM symbol: " + safeMessage(exception));
            }
        }
        try {
            return new EspRomSymbolPack(loaded.manifest(), DEVICE_ID, symbols);
        }
        catch (IllegalArgumentException exception) {
            throw invalid("Invalid ROM symbol pack: " + safeMessage(exception));
        }
    }

    public static EspPeripheralPack loadPeripherals(Path directory, ParserLimits limits,
            CancellationToken cancellation) throws DiagnosticException {
        LoadedContent loaded = loadVerified(directory, PERIPHERAL_PACK_ID,
            "peripherals.json", limits, cancellation);
        Map<String, Object> root = object(StrictJsonParser.parse(loaded.bytes(), limits,
            cancellation), "Peripheral pack root must be an object");
        exact(root, Set.of("schemaId", "deviceId", "sourceRevision", "sourceFiles",
            "peripherals"));
        requireIdentity(root, PERIPHERAL_SCHEMA, loaded.manifest());
        List<EspPeripheral> peripherals = new ArrayList<>();
        for (Object value : array(root.get("peripherals"),
                "Peripherals must be an array")) {
            cancellation.throwIfCancellationRequested();
            peripherals.add(parsePeripheral(value));
        }
        try {
            return new EspPeripheralPack(loaded.manifest(), DEVICE_ID, peripherals);
        }
        catch (IllegalArgumentException exception) {
            throw invalid("Invalid peripheral pack: " + safeMessage(exception));
        }
    }

    private static EspPeripheral parsePeripheral(Object value) throws DiagnosticException {
        Map<String, Object> peripheral = object(value, "Peripheral must be an object");
        exact(peripheral, Set.of("name", "aliases", "baseAddress", "endExclusive",
            "registers"));
        List<EspPeripheralRegister> registers = new ArrayList<>();
        for (Object registerValue : array(peripheral.get("registers"),
                "Registers must be an array")) {
            Map<String, Object> register = object(registerValue,
                "Peripheral register must be an object");
            exact(register, Set.of("address", "widthBits", "names", "sourceFiles"));
            long width = integer(register, "widthBits");
            if (width > Integer.MAX_VALUE) {
                throw invalid("Register width is out of range");
            }
            try {
                registers.add(new EspPeripheralRegister(integer(register, "address"),
                    (int) width, strings(register.get("names"), "Register names"),
                    strings(register.get("sourceFiles"), "Register sources")));
            }
            catch (IllegalArgumentException | NullPointerException exception) {
                throw invalid("Invalid peripheral register: " + safeMessage(exception));
            }
        }
        try {
            return new EspPeripheral(string(peripheral, "name"),
                strings(peripheral.get("aliases"), "Peripheral aliases"),
                integer(peripheral, "baseAddress"),
                integer(peripheral, "endExclusive"), registers);
        }
        catch (IllegalArgumentException | NullPointerException exception) {
            throw invalid("Invalid peripheral: " + safeMessage(exception));
        }
    }

    private static LoadedContent loadVerified(Path directory, String expectedPackId,
            String expectedFile, ParserLimits limits, CancellationToken cancellation)
            throws DiagnosticException {
        cancellation.throwIfCancellationRequested();
        PackManifest manifest = PackManifest.read(directory.resolve("pack.json"), limits,
            cancellation);
        if (!manifest.packId().equals(expectedPackId)
            || !manifest.supportedDevices().equals(List.of(DEVICE_ID))
            || manifest.files().size() != 1
            || !manifest.files().get(0).path().equals(expectedFile)) {
            throw PackDiagnostics.failure(DiagnosticCode.PACK_INCOMPATIBLE,
                "Pack identity, device, or content kind is incompatible");
        }
        PackIntegrity.verify(directory, manifest, limits, cancellation);
        try {
            return new LoadedContent(manifest, Files.readAllBytes(directory.resolve(expectedFile)));
        }
        catch (IOException exception) {
            throw PackDiagnostics.failure(DiagnosticCode.PACK_CONTENT_INVALID,
                "Verified pack content could not be read");
        }
    }

    private static void requireIdentity(Map<String, Object> root, String schema,
            PackManifest manifest) throws DiagnosticException {
        if (!string(root, "schemaId").equals(schema)
            || !string(root, "deviceId").equals(DEVICE_ID)
            || !string(root, "sourceRevision").equals(manifest.provenance().revision())) {
            throw PackDiagnostics.failure(DiagnosticCode.PACK_INCOMPATIBLE,
                "Pack content identity does not match its manifest");
        }
        List<String> sourceFiles = strings(root.get("sourceFiles"), "Pack source files");
        if (sourceFiles.isEmpty() || new HashSet<>(sourceFiles).size() != sourceFiles.size()
            || sourceFiles.stream().anyMatch(path -> !PackFile.isSafeRelativePath(path))) {
            throw invalid("Pack source-file evidence is invalid");
        }
    }

    private static Map<String, Object> object(Object value, String message)
            throws DiagnosticException {
        if (!(value instanceof Map<?, ?> map)) {
            throw invalid(message);
        }
        Map<String, Object> result = new LinkedHashMap<>();
        for (Map.Entry<?, ?> entry : map.entrySet()) {
            if (!(entry.getKey() instanceof String key)) {
                throw invalid(message);
            }
            result.put(key, entry.getValue());
        }
        return result;
    }

    private static List<Object> array(Object value, String message)
            throws DiagnosticException {
        if (!(value instanceof List<?> list)) {
            throw invalid(message);
        }
        return new ArrayList<>(list);
    }

    private static List<String> strings(Object value, String message)
            throws DiagnosticException {
        List<String> result = new ArrayList<>();
        for (Object item : array(value, message + " must be an array")) {
            if (!(item instanceof String text)) {
                throw invalid(message + " must contain strings");
            }
            result.add(text);
        }
        return List.copyOf(result);
    }

    private static String string(Map<String, Object> map, String field)
            throws DiagnosticException {
        Object value = map.get(field);
        if (!(value instanceof String text)) {
            throw invalid("Pack field must be a string: " + field);
        }
        return text;
    }

    private static long integer(Map<String, Object> map, String field)
            throws DiagnosticException {
        Object value = map.get(field);
        if (!(value instanceof Long number)) {
            throw invalid("Pack field must be an integer: " + field);
        }
        return number;
    }

    private static void exact(Map<String, Object> map, Set<String> fields)
            throws DiagnosticException {
        if (!map.keySet().equals(fields)) {
            throw invalid("Pack content fields do not match schema");
        }
    }

    private static DiagnosticException invalid(String message) {
        return PackDiagnostics.failure(DiagnosticCode.PACK_CONTENT_INVALID, message);
    }

    private static String safeMessage(Exception exception) {
        return exception.getMessage() == null ? "invalid value" : exception.getMessage();
    }

    private record LoadedContent(PackManifest manifest, byte[] bytes) {
        private LoadedContent {
            bytes = bytes.clone();
        }

        @Override
        public byte[] bytes() {
            return bytes.clone();
        }
    }
}
