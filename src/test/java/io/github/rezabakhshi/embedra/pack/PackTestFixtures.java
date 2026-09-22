package io.github.rezabakhshi.embedra.pack;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

final class PackTestFixtures {
    static final byte[] CONTENT = "hello".getBytes(StandardCharsets.UTF_8);

    static final String FILE_DIGEST = sha256(CONTENT);

    static final String CONTENT_DIGEST = sha256(
        ("data/payload.bin\0" + CONTENT.length + "\0" + FILE_DIGEST + "\n")
            .getBytes(StandardCharsets.UTF_8));

    private PackTestFixtures() {
    }

    static String manifest(String packId, String version, String device) {
        return """
            {
              "schemaId": "urn:embedra:schema:pack-manifest:1",
              "packId": "%s",
              "version": "%s",
              "contentDigest": "%s",
              "supportedDevices": ["%s"],
              "provenance": {
                "source": "https://example.invalid/vendor/source",
                "revision": "fixture-revision",
                "license": "Apache-2.0",
                "transformation": "Synthetic T006 fixture generated in tests",
                "redistribution": "ALLOWED"
              },
              "files": [
                {"path": "data/payload.bin", "size": %d, "sha256": "%s"}
              ]
            }
            """.formatted(packId, version, CONTENT_DIGEST, device, CONTENT.length, FILE_DIGEST);
    }

    static Path createPack(Path parent, String directory, String packId, String version, String device)
            throws IOException {
        Path pack = Files.createDirectory(parent.resolve(directory));
        Files.createDirectories(pack.resolve("data"));
        Files.write(pack.resolve("data/payload.bin"), CONTENT);
        Files.writeString(pack.resolve("pack.json"), manifest(packId, version, device),
            StandardCharsets.UTF_8);
        return pack;
    }

    static String sha256(byte[] bytes) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        }
        catch (NoSuchAlgorithmException exception) {
            throw new AssertionError(exception);
        }
    }
}
