package io.github.rezabakhshi.embedra.pack;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class PackIntegrityTest {
    @TempDir
    Path temporaryDirectory;

    @Test
    void verifiesEveryFileAndAggregateDigest() throws IOException, DiagnosticException {
        Path source = PackTestFixtures.createPack(temporaryDirectory, "source",
            "vendor.synthetic", "1.0.0", "device-a");
        PackManifest manifest = PackManifest.read(source.resolve("pack.json"),
            ParserLimits.defaults(), CancellationToken.none());

        PackIntegrity.verify(source, manifest, ParserLimits.defaults(), CancellationToken.none());
        assertEquals(PackTestFixtures.CONTENT_DIGEST,
            PackIntegrity.contentDigest(manifest.files()));
    }

    @Test
    void rejectsAlteredMissingUnexpectedAndSymlinkedContent() throws IOException {
        Path altered = PackTestFixtures.createPack(temporaryDirectory, "altered",
            "vendor.altered", "1.0.0", "device-a");
        Files.writeString(altered.resolve("data/payload.bin"), "changed", StandardCharsets.UTF_8);
        assertVerifyCode(altered, DiagnosticCode.PACK_INTEGRITY_MISMATCH);

        Path missing = PackTestFixtures.createPack(temporaryDirectory, "missing",
            "vendor.missing", "1.0.0", "device-a");
        Files.delete(missing.resolve("data/payload.bin"));
        assertVerifyCode(missing, DiagnosticCode.PACK_INTEGRITY_MISMATCH);

        Path unexpected = PackTestFixtures.createPack(temporaryDirectory, "unexpected",
            "vendor.unexpected", "1.0.0", "device-a");
        Files.writeString(unexpected.resolve("extra.bin"), "extra", StandardCharsets.UTF_8);
        assertVerifyCode(unexpected, DiagnosticCode.PACK_INTEGRITY_MISMATCH);

        Path linked = PackTestFixtures.createPack(temporaryDirectory, "linked",
            "vendor.linked", "1.0.0", "device-a");
        Files.delete(linked.resolve("data/payload.bin"));
        Files.createSymbolicLink(linked.resolve("data/payload.bin"), unexpected.resolve("extra.bin"));
        assertVerifyCode(linked, DiagnosticCode.PACK_PATH_UNSAFE);
    }

    @Test
    void checksCancellationWhileHashing() throws IOException, DiagnosticException {
        Path source = PackTestFixtures.createPack(temporaryDirectory, "cancelled",
            "vendor.cancelled", "1.0.0", "device-a");
        PackManifest manifest = PackManifest.read(source.resolve("pack.json"),
            ParserLimits.defaults(), CancellationToken.none());

        DiagnosticException exception = assertThrows(DiagnosticException.class,
            () -> PackIntegrity.verify(source, manifest, ParserLimits.defaults(), () -> true));
        assertEquals(DiagnosticCode.CANCELLED, exception.diagnostic().code());
    }

    private static void assertVerifyCode(Path pack, DiagnosticCode expected) throws IOException {
        try {
            PackManifest manifest = PackManifest.read(pack.resolve("pack.json"),
                ParserLimits.defaults(), CancellationToken.none());
            DiagnosticException exception = assertThrows(DiagnosticException.class,
                () -> PackIntegrity.verify(pack, manifest, ParserLimits.defaults(),
                    CancellationToken.none()));
            assertEquals(expected, exception.diagnostic().code());
        }
        catch (DiagnosticException exception) {
            throw new AssertionError(exception);
        }
    }
}
