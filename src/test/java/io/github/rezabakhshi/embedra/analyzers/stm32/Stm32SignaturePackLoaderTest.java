package io.github.rezabakhshi.embedra.analyzers.stm32;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class Stm32SignaturePackLoaderTest {
    private static final Path SHIPPED = Path.of("packs/stm32.stm32f1.signatures/1.0.0");

    private static final String PATTERN_HEX = "0011223344556677";

    private static final String MASK_HEX = "ffffffffffffffff";

    @TempDir
    Path temporary;

    @Test
    void loadsShippedPackWithPinnedProvenance() throws Exception {
        Stm32SignaturePack pack = load(SHIPPED);
        assertEquals(Stm32SignaturePackLoader.PACK_ID, pack.manifest().packId());
        assertEquals(Stm32SignaturePackLoader.SOURCE_PACKAGE,
            pack.manifest().provenance().revision());
        assertEquals(Stm32SignaturePackLoader.LICENSE, pack.manifest().provenance().license());
        assertEquals(java.util.List.of(Stm32SignaturePackLoader.SERIES),
            pack.manifest().supportedDevices());
        assertEquals(1543, pack.signatures().size());
        assertTrue(pack.signatures().stream()
            .anyMatch(signature -> signature.functionName().equals("HAL_Init")));
        assertTrue(pack.signatures().stream()
            .anyMatch(signature -> signature.library().equals("freertos-kernel")));
    }

    @Test
    void loadsMinimalPack() throws Exception {
        Stm32SignaturePack pack = load(writePack(content(signatureJson("one", "One", "STM32F1")),
            Stm32SignaturePackLoader.PACK_ID, Stm32SignaturePackLoader.LICENSE));
        assertEquals(1, pack.signatures().size());
        assertEquals("One", pack.signatures().get(0).functionName());
    }

    @Test
    void rejectsIdentityAndProvenanceMismatch() throws Exception {
        Path identity = writePack(content(signatureJson("one", "One", "STM32F1")),
            "stm32.other.signatures", Stm32SignaturePackLoader.LICENSE);
        assertEquals(DiagnosticCode.PACK_INCOMPATIBLE,
            loadFailure(identity).diagnostic().code());

        Path license = writePack(content(signatureJson("one", "One", "STM32F1")),
            Stm32SignaturePackLoader.PACK_ID, "SLA0044");
        assertEquals(DiagnosticCode.PACK_PROVENANCE_INVALID,
            loadFailure(license).diagnostic().code());
    }

    @Test
    void rejectsTamperedContent() throws Exception {
        Path pack = writePack(content(signatureJson("one", "One", "STM32F1")),
            Stm32SignaturePackLoader.PACK_ID, Stm32SignaturePackLoader.LICENSE);
        Files.write(pack.resolve("signatures.json"), " ".getBytes(StandardCharsets.US_ASCII),
            StandardOpenOption.APPEND);
        assertEquals(DiagnosticCode.PACK_INTEGRITY_MISMATCH,
            loadFailure(pack).diagnostic().code());
    }

    @Test
    void rejectsClosedSchemaViolations() throws Exception {
        assertInvalid(content(signatureJson("one", "One", "STM32F1"))
            .replace(",\"mask\":\"" + MASK_HEX + "\"", ""));
        assertInvalid(content(signatureJson("one", "One", "STM32F1"))
            .replace("0011223344556677", "00112233445566"));
        assertInvalid(content(signatureJson("one", "One", "STM32F1"))
            .replace("0011223344556677", "00112233445566gg"));
        assertInvalid(content(signatureJson("one", "One", "STM32F1"),
            signatureJson("one", "One", "STM32F1")));
        assertInvalid(content(signatureJson("one", "One", "STM32F1"))
            .replace("{\"signatureId\"", "{\"unexpected\":1,\"signatureId\""));
        assertInvalid(content());

        Path series = writePack(content(signatureJson("one", "One", "STM32F1"))
            .replace("\"series\":\"STM32F1\"", "\"series\":\"STM32F4\""),
            Stm32SignaturePackLoader.PACK_ID, Stm32SignaturePackLoader.LICENSE);
        assertEquals(DiagnosticCode.PACK_INCOMPATIBLE,
            loadFailure(series).diagnostic().code());
    }

    @Test
    void rejectsOversizedInputAndMissingDirectory() {
        ParserLimits tiny = new ParserLimits(16, 1024, 1024, 100, 32,
            Duration.ofSeconds(30));
        DiagnosticException limited = assertThrows(DiagnosticException.class,
            () -> Stm32SignaturePackLoader.load(SHIPPED, tiny, CancellationToken.none()));
        assertEquals(DiagnosticCode.LIMIT_EXCEEDED, limited.diagnostic().code());
        assertThrows(DiagnosticException.class, () -> load(temporary.resolve("absent")));
    }

    private void assertInvalid(String body) throws IOException {
        Path pack = writePack(body, Stm32SignaturePackLoader.PACK_ID,
            Stm32SignaturePackLoader.LICENSE);
        assertEquals(DiagnosticCode.PACK_CONTENT_INVALID,
            loadFailure(pack).diagnostic().code());
    }

    private static Stm32SignaturePack load(Path directory)
            throws IOException, DiagnosticException {
        return Stm32SignaturePackLoader.load(directory, ParserLimits.defaults(),
            CancellationToken.none());
    }

    private static DiagnosticException loadFailure(Path directory) {
        return assertThrows(DiagnosticException.class, () -> load(directory));
    }

    private Path writePack(String body, String packId, String license) throws IOException {
        Path directory = Files.createDirectory(
            temporary.resolve("pack" + System.nanoTime()));
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        Files.write(directory.resolve("signatures.json"), bytes);
        String sha = sha256(bytes);
        String digest = sha256(("signatures.json\0" + bytes.length + "\0" + sha + "\n")
            .getBytes(StandardCharsets.UTF_8));
        Files.writeString(directory.resolve("pack.json"),
            "{\"schemaId\":\"urn:embedra:schema:pack-manifest:1\",\"packId\":\"" + packId
                + "\",\"version\":\"1.0.0\",\"contentDigest\":\"" + digest
                + "\",\"supportedDevices\":[\"STM32F1\"],\"provenance\":{"
                + "\"source\":\"https://github.com/STMicroelectronics/STM32CubeF1\","
                + "\"revision\":\"" + Stm32SignaturePackLoader.SOURCE_PACKAGE
                + "\",\"license\":\"" + license + "\",\"transformation\":\"test\","
                + "\"redistribution\":\"ALLOWED\"},\"files\":[{\"path\":\"signatures.json\","
                + "\"size\":" + bytes.length + ",\"sha256\":\"" + sha + "\"}]}");
        return directory;
    }

    private static String content(String... signatureObjects) {
        return "{\"$schema\":\"" + Stm32SignaturePackLoader.CONTENT_SCHEMA
            + "\",\"series\":\"STM32F1\",\"sourcePackage\":\""
            + Stm32SignaturePackLoader.SOURCE_PACKAGE + "\",\"signatures\":["
            + String.join(",", signatureObjects) + "]}";
    }

    private static String signatureJson(String id, String functionName, String series) {
        return "{\"signatureId\":\"" + id + "\",\"library\":\"stm32f1xx-hal\","
            + "\"component\":\"stm32f1xx-hal\",\"functionName\":\"" + functionName + "\","
            + "\"family\":\"" + series + "\",\"compiler\":\""
            + Stm32SignatureTestSupport.COMPILER + "\",\"optimization\":\"-Os\","
            + "\"sourceFile\":\"f.c\",\"sourceSha256\":\""
            + Stm32SignatureTestSupport.SOURCE_SHA + "\",\"pattern\":\"" + PATTERN_HEX
            + "\",\"mask\":\"" + MASK_HEX + "\"}";
    }

    private static String sha256(byte[] data) {
        try {
            return HexFormat.of().formatHex(
                MessageDigest.getInstance("SHA-256").digest(data));
        }
        catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException(exception);
        }
    }
}
