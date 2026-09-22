package io.github.rezabakhshi.embedra.pack;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import org.junit.jupiter.api.Test;

class PackManifestTest {
    @Test
    void parsesCompleteManifestAndEmitsCanonicalJson() throws DiagnosticException {
        PackManifest manifest = PackManifest.parse(bytes(PackTestFixtures.manifest(
            "vendor.synthetic", "1.2.0", "device-a")), ParserLimits.defaults(),
            CancellationToken.none());

        assertEquals(PackManifest.SCHEMA_ID, manifest.schemaId());
        assertEquals("vendor.synthetic", manifest.packId());
        assertEquals(PackVersion.parse("1.2.0"), manifest.version());
        assertEquals("Apache-2.0", manifest.provenance().license());
        assertEquals(RedistributionStatus.ALLOWED, manifest.provenance().redistribution());
        assertEquals(PackTestFixtures.CONTENT_DIGEST, manifest.contentDigest());
        assertEquals("data/payload.bin", manifest.files().getFirst().path());
        assertTrue(manifest.toCanonicalJson().startsWith("{\"contentDigest\":"));
    }

    @Test
    void rejectsMalformedUnknownVersionedAndIncompleteManifests() {
        assertCode(DiagnosticCode.PACK_MANIFEST_INVALID, "{}");
        assertCode(DiagnosticCode.PACK_MANIFEST_INVALID,
            PackTestFixtures.manifest("vendor.synthetic", "1.0.0", "device-a")
                .replaceFirst("\\{", "{\"unexpected\":true,"));
        assertCode(DiagnosticCode.PACK_SCHEMA_UNSUPPORTED,
            PackTestFixtures.manifest("vendor.synthetic", "1.0.0", "device-a")
                .replace(PackManifest.SCHEMA_ID, "urn:embedra:schema:pack-manifest:999"));
        assertCode(DiagnosticCode.PACK_PROVENANCE_INVALID,
            PackTestFixtures.manifest("vendor.synthetic", "1.0.0", "device-a")
                .replace("Apache-2.0", " "));
        assertCode(DiagnosticCode.PACK_MANIFEST_INVALID,
            PackTestFixtures.manifest("vendor.synthetic", "next", "device-a"));
        assertCode(DiagnosticCode.PACK_PATH_UNSAFE,
            PackTestFixtures.manifest("vendor.synthetic", "1.0.0", "device-a")
                .replace("data/payload.bin", "../payload.bin"));
        assertCode(DiagnosticCode.PACK_PATH_UNSAFE,
            PackTestFixtures.manifest("vendor.synthetic", "1.0.0", "device-a")
                .replace("data/payload.bin", "C:/payload.bin"));
        assertCode(DiagnosticCode.PACK_INTEGRITY_MISMATCH,
            PackTestFixtures.manifest("vendor.synthetic", "1.0.0", "device-a")
                .replace(PackTestFixtures.CONTENT_DIGEST, "0".repeat(64)));
        assertCode(DiagnosticCode.PACK_PROVENANCE_INVALID,
            PackTestFixtures.manifest("vendor.synthetic", "1.0.0", "device-a")
                .replace("ALLOWED", "UNKNOWN"));
        assertCode(DiagnosticCode.PACK_MANIFEST_INVALID,
            PackTestFixtures.manifest("vendor.synthetic", "1.0.0", "device-a")
                .replace("\"size\": 5", "\"size\": 5.0"));
        assertCode(DiagnosticCode.PACK_MANIFEST_INVALID,
            PackTestFixtures.manifest("vendor.synthetic", "1.0.0", "device-a")
                .replaceFirst("\"schemaId\":", "\"schemaId\": \"duplicate\", \"schemaId\":"));
        assertCode(DiagnosticCode.PACK_MANIFEST_INVALID, new byte[] {(byte) 0xc3, (byte) 0x28});
    }

    @Test
    void enforcesCancellationInputObjectAndNestingLimits() {
        assertCode(DiagnosticCode.CANCELLED,
            PackTestFixtures.manifest("vendor.synthetic", "1.0.0", "device-a"), () -> true,
            ParserLimits.defaults());
        assertCode(DiagnosticCode.LIMIT_EXCEEDED,
            PackTestFixtures.manifest("vendor.synthetic", "1.0.0", "device-a"),
            CancellationToken.none(), new ParserLimits(32, 32, 32, 100, 8, Duration.ofSeconds(1)));
        assertCode(DiagnosticCode.LIMIT_EXCEEDED,
            PackTestFixtures.manifest("vendor.synthetic", "1.0.0", "device-a"),
            CancellationToken.none(), new ParserLimits(4096, 4096, 4096, 3, 8,
                Duration.ofSeconds(1)));
        assertCode(DiagnosticCode.LIMIT_EXCEEDED,
            PackTestFixtures.manifest("vendor.synthetic", "1.0.0", "device-a"),
            CancellationToken.none(), new ParserLimits(4096, 4096, 4096, 100, 1,
                Duration.ofSeconds(1)));
    }

    private static byte[] bytes(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }

    private static void assertCode(DiagnosticCode code, String manifest) {
        assertCode(code, manifest, CancellationToken.none(), ParserLimits.defaults());
    }

    private static void assertCode(DiagnosticCode code, byte[] manifest) {
        DiagnosticException exception = assertThrows(DiagnosticException.class,
            () -> PackManifest.parse(manifest, ParserLimits.defaults(), CancellationToken.none()));
        assertEquals(code, exception.diagnostic().code());
    }

    private static void assertCode(
            DiagnosticCode code, String manifest, CancellationToken token, ParserLimits limits) {
        DiagnosticException exception = assertThrows(DiagnosticException.class,
            () -> PackManifest.parse(bytes(manifest), limits, token));
        assertEquals(code, exception.diagnostic().code());
    }
}
