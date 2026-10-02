package io.github.rezabakhshi.embedra.pack;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class Stm32SvdPackLoaderTest {
    private static final Path F103 = Path.of("packs/stm32.stm32f103.svd/1.0.0");

    @TempDir
    Path temporary;

    @Test
    void loadsShippedPackWithPinnedProvenance() throws Exception {
        Stm32SvdPack pack = load(F103);
        assertEquals("stm32.stm32f103.svd", pack.manifest().packId());
        assertEquals("STM32F103", pack.device().name());
        assertEquals("CM3", pack.cpu());
        assertEquals("stm32f1/STM32F103.svd", pack.sourceFile());
        assertEquals(64, pack.sourceFileSha256().length());
        assertEquals("Apache-2.0", pack.manifest().provenance().license());
        assertTrue(pack.manifest().supportedDevices()
            .containsAll(java.util.List.of("STM32F103C8T6", "STM32F103CBT6")));
        assertTrue(pack.registerCount() > 300);
        assertTrue(pack.fieldCount() > 3_000);
        assertEquals("RCC", pack.device().requirePeripheral("RCC").interrupts()
            .get(0).name());
    }

    @Test
    void rejectsTamperedContentAndUnsafePaths() throws Exception {
        Path copy = copyPack();
        Files.write(copy.resolve("registers.json"),
            " ".getBytes(StandardCharsets.US_ASCII), java.nio.file.StandardOpenOption.APPEND);
        assertThrows(DiagnosticException.class, () -> load(copy));
        assertThrows(DiagnosticException.class,
            () -> load(temporary.resolve("absent")));
    }

    @Test
    void rejectsIncompatibleIdentityAndProvenance() throws Exception {
        Path identity = copyPack();
        String manifest = Files.readString(identity.resolve("pack.json"));
        Files.writeString(identity.resolve("pack.json"),
            manifest.replace("\"packId\":\"stm32.stm32f103.svd\"",
                "\"packId\":\"stm32.other.svd\""));
        DiagnosticException incompatible = assertThrows(DiagnosticException.class,
            () -> load(identity));
        assertEquals(DiagnosticCode.PACK_INCOMPATIBLE, incompatible.diagnostic().code());

        Path license = copyPack();
        String licensed = Files.readString(license.resolve("pack.json"));
        Files.writeString(license.resolve("pack.json"),
            licensed.replace("Apache-2.0", "SLA0044"));
        DiagnosticException provenance = assertThrows(DiagnosticException.class,
            () -> load(license));
        assertEquals(DiagnosticCode.PACK_PROVENANCE_INVALID, provenance.diagnostic().code());
    }

    @Test
    void rejectsClosedSchemaViolations() throws Exception {
        Path copy = copyPack();
        Path content = copy.resolve("registers.json");
        String body = Files.readString(content)
            .replace("urn:embedra:schema:stm32-svd-pack:1", "urn:embedra:schema:other:1");
        Files.writeString(content, body);
        rewriteManifest(copy, body.getBytes(StandardCharsets.UTF_8));
        DiagnosticException schema = assertThrows(DiagnosticException.class,
            () -> load(copy));
        assertEquals(DiagnosticCode.PACK_INCOMPATIBLE, schema.diagnostic().code());

        Path trimmed = copyPack();
        Path trimmedContent = trimmed.resolve("registers.json");
        String payload = Files.readString(trimmedContent)
            .replace("\"cpu\":\"CM3\",", "");
        Files.writeString(trimmedContent, payload);
        rewriteManifest(trimmed, payload.getBytes(StandardCharsets.UTF_8));
        DiagnosticException closed = assertThrows(DiagnosticException.class,
            () -> load(trimmed));
        assertEquals(DiagnosticCode.PACK_CONTENT_INVALID, closed.diagnostic().code());
        assertFalse(Files.exists(temporary.resolve("never")));
    }

    @Test
    void rejectsOutOfRangeInterruptValueWithTypedDiagnostic() throws Exception {
        Path copy = copyPack();
        Path content = copy.resolve("registers.json");
        String body = Files.readString(content);
        String updated = java.util.regex.Pattern
            .compile("(\"interrupts\":\\[\\{[^\\]]*?\"value\":)-?[0-9]+")
            .matcher(body).replaceFirst(match -> match.group(1) + "999999999999");
        assertNotEquals(body, updated);
        Files.writeString(content, updated);
        rewriteManifest(copy, updated.getBytes(StandardCharsets.UTF_8));
        DiagnosticException error = assertThrows(DiagnosticException.class, () -> load(copy));
        assertEquals(DiagnosticCode.PACK_CONTENT_INVALID, error.diagnostic().code());
    }

    private Stm32SvdPack load(Path directory) throws IOException, DiagnosticException {
        return Stm32SvdPackLoader.load(directory, ParserLimits.defaults(),
            CancellationToken.none());
    }

    private Path copyPack() throws IOException {
        Path target = temporary.resolve("pack" + System.nanoTime());
        try (var stream = Files.walk(F103)) {
            for (Path source : stream.toList()) {
                Path relative = F103.relativize(source);
                Path destination = target.resolve(relative.toString());
                if (Files.isDirectory(source)) {
                    Files.createDirectories(destination);
                }
                else {
                    Files.createDirectories(destination.getParent());
                    Files.copy(source, destination);
                }
            }
        }
        return target;
    }

    private static void rewriteManifest(Path pack, byte[] content) throws IOException {
        String sha = sha256(content);
        String digest = sha256(("registers.json\0" + content.length + "\0" + sha
            + "\n").getBytes(StandardCharsets.UTF_8));
        String manifest = "{\"schemaId\":\"urn:embedra:schema:pack-manifest:1\","
            + "\"packId\":\"stm32.stm32f103.svd\",\"version\":\"1.0.0\","
            + "\"contentDigest\":\"" + digest + "\","
            + "\"supportedDevices\":[\"STM32F103C8T6\",\"STM32F103CBT6\","
            + "\"STM32F103RBT6\"],\"provenance\":{"
            + "\"source\":\"https://github.com/modm-io/cmsis-svd-stm32\","
            + "\"revision\":\"e79021accd49bf19bd0b16065f5471fb073ff3ac\","
            + "\"license\":\"Apache-2.0\",\"transformation\":\"test\","
            + "\"redistribution\":\"ALLOWED\"},\"files\":[{\"path\":\"registers.json\","
            + "\"size\":" + content.length + ",\"sha256\":\"" + sha + "\"}]}";
        Files.writeString(pack.resolve("pack.json"), manifest);
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
