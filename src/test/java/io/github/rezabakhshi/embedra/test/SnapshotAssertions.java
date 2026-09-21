package io.github.rezabakhshi.embedra.test;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

public final class SnapshotAssertions {
    private SnapshotAssertions() {
    }

    public static void assertMatches(String resourceName, String actual) {
        try (InputStream stream = SnapshotAssertions.class.getClassLoader().getResourceAsStream(resourceName)) {
            if (stream == null) {
                throw new AssertionError("Missing snapshot resource: " + resourceName);
            }
            String expected = new String(stream.readAllBytes(), StandardCharsets.UTF_8);
            assertEquals(expected, actual, "Canonical snapshot changed: " + resourceName);
        }
        catch (IOException exception) {
            throw new AssertionError("Cannot read snapshot resource: " + resourceName, exception);
        }
    }
}
