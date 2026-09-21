package io.github.rezabakhshi.embedra.build;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;
import org.junit.jupiter.api.Test;

class BuildConfigurationTest {
    private static final Path PROJECT_DIRECTORY =
        Path.of(System.getProperty("embedra.projectDir")).toAbsolutePath().normalize();

    @Test
    void pinsGradleWrapper() throws IOException {
        Properties wrapper = loadProperties("gradle/wrapper/gradle-wrapper.properties");

        assertTrue(
            wrapper.getProperty("distributionUrl").endsWith("/gradle-9.6.1-bin.zip"),
            "Gradle Wrapper must remain pinned to 9.6.1");
        assertEquals("true", wrapper.getProperty("validateDistributionUrl"));
    }

    @Test
    void preservesGhidraExtensionBuildTokens() throws IOException {
        Properties extension = loadProperties("extension.properties");

        assertEquals("@extname@", extension.getProperty("name"));
        assertEquals("@extversion@", extension.getProperty("version"));
    }

    private static Properties loadProperties(String relativePath) throws IOException {
        Properties properties = new Properties();
        Path path = PROJECT_DIRECTORY.resolve(relativePath).normalize();
        assertTrue(path.startsWith(PROJECT_DIRECTORY), "Test path escaped the project directory");
        try (Reader reader = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
            properties.load(reader);
        }
        return properties;
    }
}
