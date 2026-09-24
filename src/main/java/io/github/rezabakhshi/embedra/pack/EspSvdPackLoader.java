package io.github.rezabakhshi.embedra.pack;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.svd.EspSvdAccess;
import io.github.rezabakhshi.embedra.svd.EspSvdDevice;
import io.github.rezabakhshi.embedra.svd.EspSvdField;
import io.github.rezabakhshi.embedra.svd.EspSvdEnumeratedValue;
import io.github.rezabakhshi.embedra.svd.EspSvdPeripheral;
import io.github.rezabakhshi.embedra.svd.EspSvdRegister;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.OptionalLong;
import java.util.Set;

/** Integrity-first loader for generated ESP-family SVD packs. */
public final class EspSvdPackLoader {
    private static final String CONTENT_FILE = "registers.json";

    private static final String CONTENT_SCHEMA = "urn:embedra:schema:esp-svd-pack:1";

    private EspSvdPackLoader() {
    }

    public static EspSvdPack load(Path directory, ParserLimits limits,
            CancellationToken token) throws DiagnosticException {
        return load(directory, "esp32s3", limits, token);
    }

    public static EspSvdPack load(Path directory, String deviceId, ParserLimits limits,
            CancellationToken token) throws DiagnosticException {
        token.throwIfCancellationRequested();
        String expectedPackId = "espressif." + deviceId + ".svd";
        PackManifest manifest = PackManifest.read(directory.resolve("pack.json"), limits,
            token);
        if (!manifest.packId().equals(expectedPackId)
            || !manifest.supportedDevices().equals(List.of(deviceId))
            || manifest.files().size() != 1
            || !manifest.files().get(0).path().equals(CONTENT_FILE)) {
            throw failure(DiagnosticCode.PACK_INCOMPATIBLE,
                "SVD pack identity, device, or content kind is incompatible");
        }
        PackIntegrity.verify(directory, manifest, limits, token);
        byte[] bytes;
        try {
            bytes = Files.readAllBytes(directory.resolve(CONTENT_FILE));
        }
        catch (IOException exception) {
            throw failure(DiagnosticCode.PACK_CONTENT_INVALID,
                "Verified SVD pack content could not be read");
        }
        Map<String, Object> root = object(StrictJsonParser.parse(bytes, limits, token),
            "SVD pack root must be an object");
        exact(root, Set.of("schemaId", "deviceId", "deviceName", "sourceRevision",
            "sourceFiles", "peripherals", "reconciliation"));
        if (!string(root, "schemaId").equals(CONTENT_SCHEMA)
            || !string(root, "deviceId").equals(deviceId)
            || !string(root, "sourceRevision").equals(manifest.provenance().revision())) {
            throw failure(DiagnosticCode.PACK_INCOMPATIBLE,
                "SVD content identity does not match its manifest");
        }
        List<Object> sourceFiles = array(root.get("sourceFiles"),
            "SVD source files must be an array");
        if (sourceFiles.size() != 1 || !(sourceFiles.get(0) instanceof String sourceFile)
            || !sourceFile.equals("svd/" + deviceId + ".svd")) {
            throw invalid("SVD source-file provenance is invalid");
        }
        List<EspSvdPeripheral> peripherals = new ArrayList<>();
        for (Object value : array(root.get("peripherals"),
                "SVD peripherals must be an array")) {
            token.throwIfCancellationRequested();
            peripherals.add(peripheral(value));
        }
        EspSvdDevice device;
        try {
            device = new EspSvdDevice(string(root, "deviceName"),
                string(root, "sourceRevision"), peripherals);
        }
        catch (IllegalArgumentException exception) {
            throw invalid("Invalid SVD device: " + safeMessage(exception));
        }
        Map<String, Object> evidence = object(root.get("reconciliation"),
            "SVD reconciliation must be an object");
        exact(evidence, Set.of("headerPackContentSha256", "matchingPeripheralBases",
            "matchingRegisterAddresses", "policy"));
        try {
            EspSvdReconciliation reconciliation = new EspSvdReconciliation(
                string(evidence, "headerPackContentSha256"),
                integer(evidence, "matchingPeripheralBases"),
                integer(evidence, "matchingRegisterAddresses"),
                string(evidence, "policy"));
            return new EspSvdPack(manifest, device, reconciliation);
        }
        catch (IllegalArgumentException exception) {
            throw invalid("Invalid SVD reconciliation: " + safeMessage(exception));
        }
    }

    private static EspSvdPeripheral peripheral(Object value) throws DiagnosticException {
        Map<String, Object> item = object(value, "SVD peripheral must be an object");
        exact(item, Set.of("name", "description", "baseAddress", "endExclusive",
            "registers"));
        List<EspSvdRegister> registers = new ArrayList<>();
        for (Object register : array(item.get("registers"),
                "SVD registers must be an array")) {
            registers.add(register(register));
        }
        try {
            return new EspSvdPeripheral(string(item, "name"),
                string(item, "description"), integer(item, "baseAddress"),
                integer(item, "endExclusive"), registers);
        }
        catch (IllegalArgumentException exception) {
            throw invalid("Invalid SVD peripheral: " + safeMessage(exception));
        }
    }

    private static EspSvdRegister register(Object value) throws DiagnosticException {
        Map<String, Object> item = object(value, "SVD register must be an object");
        exact(item, Set.of("name", "description", "address", "sizeBits", "access",
            "resetValue", "fields"));
        EspSvdAccess access = EspSvdAccess.parse(string(item, "access"),
            EspSvdAccess.UNKNOWN);
        List<EspSvdField> fields = new ArrayList<>();
        for (Object field : array(item.get("fields"), "SVD fields must be an array")) {
            fields.add(field(field, access));
        }
        Object reset = item.get("resetValue");
        OptionalLong resetValue = reset == null ? OptionalLong.empty()
            : OptionalLong.of(integerValue(reset, "SVD reset value must be an integer"));
        try {
            return new EspSvdRegister(string(item, "name"),
                string(item, "description"), integer(item, "address"),
                Math.toIntExact(integer(item, "sizeBits")), access, resetValue, fields);
        }
        catch (IllegalArgumentException | ArithmeticException exception) {
            throw invalid("Invalid SVD register: " + safeMessage(exception));
        }
    }

    private static EspSvdField field(Object value, EspSvdAccess inherited)
            throws DiagnosticException {
        Map<String, Object> item = object(value, "SVD field must be an object");
        exact(item, Set.of("name", "description", "bitOffset", "bitWidth", "access",
            "enumeratedValues"));
        List<EspSvdEnumeratedValue> values = new ArrayList<>();
        for (Object valueItem : array(item.get("enumeratedValues"),
                "SVD enumerated values must be an array")) {
            Map<String, Object> enumerated = object(valueItem,
                "SVD enumerated value must be an object");
            exact(enumerated, Set.of("name", "value", "description"));
            values.add(new EspSvdEnumeratedValue(string(enumerated, "name"),
                integer(enumerated, "value"), string(enumerated, "description")));
        }
        try {
            return new EspSvdField(string(item, "name"), string(item, "description"),
                Math.toIntExact(integer(item, "bitOffset")),
                Math.toIntExact(integer(item, "bitWidth")),
                EspSvdAccess.parse(string(item, "access"), inherited), values);
        }
        catch (IllegalArgumentException | ArithmeticException exception) {
            throw invalid("Invalid SVD field: " + safeMessage(exception));
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

    private static String string(Map<String, Object> map, String key)
            throws DiagnosticException {
        Object value = map.get(key);
        if (!(value instanceof String text)) {
            throw invalid("SVD field must be a string: " + key);
        }
        return text;
    }

    private static long integer(Map<String, Object> map, String key)
            throws DiagnosticException {
        return integerValue(map.get(key), "SVD field must be an integer: " + key);
    }

    private static long integerValue(Object value, String message)
            throws DiagnosticException {
        if (!(value instanceof Long number)) {
            throw invalid(message);
        }
        return number;
    }

    private static void exact(Map<String, Object> map, Set<String> fields)
            throws DiagnosticException {
        if (!map.keySet().equals(fields)) {
            throw invalid("SVD pack fields do not match the closed schema");
        }
    }

    private static DiagnosticException invalid(String message) {
        return failure(DiagnosticCode.PACK_CONTENT_INVALID, message);
    }

    private static DiagnosticException failure(DiagnosticCode code, String message) {
        return PackDiagnostics.failure(code, message);
    }

    private static String safeMessage(Exception exception) {
        String message = exception.getMessage();
        return message == null || message.isBlank() ? exception.getClass().getSimpleName()
            : message;
    }
}
