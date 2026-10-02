package io.github.rezabakhshi.embedra.pack;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.svd.EspSvdAccess;
import io.github.rezabakhshi.embedra.svd.Stm32SvdDevice;
import io.github.rezabakhshi.embedra.svd.Stm32SvdEnumeratedValue;
import io.github.rezabakhshi.embedra.svd.Stm32SvdField;
import io.github.rezabakhshi.embedra.svd.Stm32SvdInterrupt;
import io.github.rezabakhshi.embedra.svd.Stm32SvdPeripheral;
import io.github.rezabakhshi.embedra.svd.Stm32SvdRegister;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Set;

/** Integrity-first loader for generated STM32 CMSIS-SVD register packs. */
public final class Stm32SvdPackLoader {
    public static final String CONTENT_SCHEMA = "urn:embedra:schema:stm32-svd-pack:1";

    private static final String CONTENT_FILE = "registers.json";

    private static final String PACK_ID_PREFIX = "stm32.";

    private static final String PACK_ID_SUFFIX = ".svd";

    private static final String EXPECTED_LICENSE = "Apache-2.0";

    private static final String EXPECTED_REVISION =
        "e79021accd49bf19bd0b16065f5471fb073ff3ac";

    private Stm32SvdPackLoader() {
    }

    public static Stm32SvdPack load(Path directory, ParserLimits limits,
            CancellationToken token) throws DiagnosticException {
        token.throwIfCancellationRequested();
        PackManifest manifest = PackManifest.read(directory.resolve("pack.json"), limits, token);
        if (!manifest.packId().startsWith(PACK_ID_PREFIX)
            || !manifest.packId().endsWith(PACK_ID_SUFFIX)
            || manifest.files().size() != 1
            || !manifest.files().get(0).path().equals(CONTENT_FILE)) {
            throw failure(DiagnosticCode.PACK_INCOMPATIBLE,
                "STM32 SVD pack identity, device, or content kind is incompatible");
        }
        PackProvenance provenance = manifest.provenance();
        if (!EXPECTED_LICENSE.equals(provenance.license())
            || !EXPECTED_REVISION.equals(provenance.revision())
            || provenance.redistribution() != RedistributionStatus.ALLOWED) {
            throw failure(DiagnosticCode.PACK_PROVENANCE_INVALID,
                "STM32 SVD pack provenance is not the pinned redistributable source");
        }
        PackIntegrity.verify(directory, manifest, limits, token);
        byte[] bytes;
        try {
            bytes = Files.readAllBytes(directory.resolve(CONTENT_FILE));
        }
        catch (IOException exception) {
            throw failure(DiagnosticCode.PACK_CONTENT_INVALID,
                "Verified STM32 SVD pack content could not be read");
        }
        Map<String, Object> root = object(StrictJsonParser.parse(bytes, limits, token),
            "SVD pack root must be an object");
        exact(root, Set.of("schemaId", "deviceName", "sourceRevision", "sourceFile",
            "sourceFileSha256", "cpu", "peripherals"));
        if (!string(root, "schemaId").equals(CONTENT_SCHEMA)
            || !string(root, "sourceRevision").equals(provenance.revision())) {
            throw failure(DiagnosticCode.PACK_INCOMPATIBLE,
                "SVD content identity does not match its manifest");
        }
        String deviceName = string(root, "deviceName");
        String expectedPackId = "stm32." + deviceName.toLowerCase(java.util.Locale.ROOT)
            .replace('_', '-') + PACK_ID_SUFFIX;
        if (!manifest.packId().equals(expectedPackId)) {
            throw failure(DiagnosticCode.PACK_INCOMPATIBLE,
                "SVD pack identity does not match its device name");
        }
        String sourceFile = string(root, "sourceFile");
        String sourceFileSha256 = string(root, "sourceFileSha256");
        String cpu = nullableString(root.get("cpu"));
        if (!sourceFileSha256.matches("[0-9a-f]{64}")) {
            throw invalid("SVD source digest is not lowercase SHA-256");
        }
        List<Stm32SvdPeripheral> peripherals = new ArrayList<>();
        for (Object value : array(root.get("peripherals"),
                "SVD peripherals must be an array")) {
            token.throwIfCancellationRequested();
            peripherals.add(peripheral(value));
        }
        Stm32SvdDevice device;
        try {
            device = new Stm32SvdDevice(deviceName, provenance.revision(), peripherals);
        }
        catch (IllegalArgumentException exception) {
            throw invalid("Invalid SVD device: " + safeMessage(exception));
        }
        return new Stm32SvdPack(manifest, device, cpu, sourceFile, sourceFileSha256);
    }

    private static Stm32SvdPeripheral peripheral(Object value) throws DiagnosticException {
        Map<String, Object> item = object(value, "SVD peripheral must be an object");
        exact(item, Set.of("name", "description", "groupName", "baseAddress",
            "endExclusive", "interrupts", "registers"));
        List<Stm32SvdInterrupt> interrupts = new ArrayList<>();
        for (Object entry : array(item.get("interrupts"),
                "SVD interrupts must be an array")) {
            Map<String, Object> interrupt = object(entry, "SVD interrupt must be an object");
            exact(interrupt, Set.of("name", "value", "description"));
            int interruptValue;
            try {
                interruptValue = intValue(integer(interrupt, "value"));
            }
            catch (ArithmeticException exception) {
                throw invalid("SVD interrupt value is outside the integer range");
            }
            interrupts.add(new Stm32SvdInterrupt(string(interrupt, "name"), interruptValue,
                string(interrupt, "description")));
        }
        List<Stm32SvdRegister> registers = new ArrayList<>();
        for (Object entry : array(item.get("registers"),
                "SVD registers must be an array")) {
            registers.add(register(entry));
        }
        try {
            return new Stm32SvdPeripheral(string(item, "name"),
                string(item, "description"), string(item, "groupName"),
                integer(item, "baseAddress"), integer(item, "endExclusive"),
                registers, interrupts);
        }
        catch (IllegalArgumentException | ArithmeticException exception) {
            throw invalid("Invalid SVD peripheral: " + safeMessage(exception));
        }
    }

    private static Stm32SvdRegister register(Object value) throws DiagnosticException {
        Map<String, Object> item = object(value, "SVD register must be an object");
        exact(item, Set.of("name", "description", "address", "sizeBits", "access",
            "resetValue", "resetMask", "alternateRegister", "alternateGroup", "fields"));
        List<Stm32SvdField> fields = new ArrayList<>();
        for (Object entry : array(item.get("fields"), "SVD fields must be an array")) {
            fields.add(field(entry));
        }
        try {
            return new Stm32SvdRegister(string(item, "name"), string(item, "description"),
                integer(item, "address"), intValue(integer(item, "sizeBits")),
                access(string(item, "access")), optionalLong(item.get("resetValue")),
                optionalLong(item.get("resetMask")), fields,
                optionalString(item.get("alternateRegister")),
                optionalString(item.get("alternateGroup")));
        }
        catch (IllegalArgumentException | ArithmeticException exception) {
            throw invalid("Invalid SVD register: " + safeMessage(exception));
        }
    }

    private static Stm32SvdField field(Object value) throws DiagnosticException {
        Map<String, Object> item = object(value, "SVD field must be an object");
        exact(item, Set.of("name", "description", "bitOffset", "bitWidth", "access",
            "resetValue", "readAction", "enumeratedValues"));
        List<Stm32SvdEnumeratedValue> values = new ArrayList<>();
        for (Object entry : array(item.get("enumeratedValues"),
                "SVD enumerated values must be an array")) {
            Map<String, Object> enumerated = object(entry,
                "SVD enumerated value must be an object");
            exact(enumerated, Set.of("name", "value", "description", "isDefault"));
            values.add(new Stm32SvdEnumeratedValue(string(enumerated, "name"),
                integer(enumerated, "value"), string(enumerated, "description"),
                bool(enumerated, "isDefault")));
        }
        try {
            return new Stm32SvdField(string(item, "name"), string(item, "description"),
                intValue(integer(item, "bitOffset")), intValue(integer(item, "bitWidth")),
                access(string(item, "access")), optionalLong(item.get("resetValue")),
                optionalString(item.get("readAction")), values);
        }
        catch (IllegalArgumentException | ArithmeticException exception) {
            throw invalid("Invalid SVD field: " + safeMessage(exception));
        }
    }

    private static EspSvdAccess access(String value) {
        try {
            return EspSvdAccess.valueOf(value);
        }
        catch (IllegalArgumentException exception) {
            throw new IllegalArgumentException("Unsupported SVD access value: " + value);
        }
    }

    private static OptionalLong optionalLong(Object value) throws DiagnosticException {
        if (value == null) {
            return OptionalLong.empty();
        }
        return OptionalLong.of(integerValue(value, "SVD value must be an integer"));
    }

    private static Optional<String> optionalString(Object value) throws DiagnosticException {
        if (value == null) {
            return Optional.empty();
        }
        if (!(value instanceof String text)) {
            throw invalid("SVD value must be a string");
        }
        return Optional.of(text);
    }

    private static String nullableString(Object value) throws DiagnosticException {
        if (value == null) {
            return null;
        }
        if (!(value instanceof String text)) {
            throw invalid("SVD value must be a string or null");
        }
        return text;
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

    private static List<Object> array(Object value, String message) throws DiagnosticException {
        if (!(value instanceof List<?> list)) {
            throw invalid(message);
        }
        return new ArrayList<>(list);
    }

    private static String string(Map<String, Object> map, String key) throws DiagnosticException {
        Object value = map.get(key);
        if (!(value instanceof String text)) {
            throw invalid("SVD field must be a string: " + key);
        }
        return text;
    }

    private static boolean bool(Map<String, Object> map, String key) throws DiagnosticException {
        Object value = map.get(key);
        if (!(value instanceof Boolean flag)) {
            throw invalid("SVD field must be a boolean: " + key);
        }
        return flag;
    }

    private static long integer(Map<String, Object> map, String key) throws DiagnosticException {
        return integerValue(map.get(key), "SVD field must be an integer: " + key);
    }

    private static long integerValue(Object value, String message) throws DiagnosticException {
        if (!(value instanceof Long number)) {
            throw invalid(message);
        }
        return number;
    }

    private static int intValue(long value) {
        return Math.toIntExact(value);
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
