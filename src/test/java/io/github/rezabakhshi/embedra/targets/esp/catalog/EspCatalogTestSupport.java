package io.github.rezabakhshi.embedra.targets.esp.catalog;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

final class EspCatalogTestSupport {
    private EspCatalogTestSupport() {
    }

    static String sha256(Path path) throws IOException {
        try {
            return HexFormat.of().formatHex(
                MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(path)));
        }
        catch (NoSuchAlgorithmException exception) {
            throw new AssertionError(exception);
        }
    }
}
