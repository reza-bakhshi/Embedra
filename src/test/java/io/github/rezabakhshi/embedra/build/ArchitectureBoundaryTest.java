package io.github.rezabakhshi.embedra.build;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

class ArchitectureBoundaryTest {
    private static final Path PROJECT_DIRECTORY =
        Path.of(System.getProperty("embedra.projectDir")).toAbsolutePath().normalize();

    private static final Path MAIN_PACKAGE = PROJECT_DIRECTORY.resolve(
        "src/main/java/io/github/rezabakhshi/embedra");

    private static final List<String> REQUIRED_BOUNDARIES = List.of(
        "core", "formats", "targets", "analyzers", "ghidra", "pack", "svd");

    private static final List<String> PURE_BOUNDARIES = List.of(
        "core", "formats", "targets", "analyzers", "pack", "svd");

    private static final Pattern GHIDRA_IMPORT = Pattern.compile(
        "^\\s*import\\s+(?:static\\s+)?(?:ghidra\\.|"
            + "io\\.github\\.rezabakhshi\\.embedra\\.ghidra\\.)");

    private static final Pattern GHIDRA_QUALIFIED_REFERENCE = Pattern.compile(
        "(?<!embedra\\.)\\bghidra\\.(?:app|framework|program|util)\\.");

    @Test
    void declaresEveryRequiredBoundary() {
        List<String> missing = REQUIRED_BOUNDARIES.stream()
            .filter(boundary -> !Files.isRegularFile(
                MAIN_PACKAGE.resolve(boundary).resolve("package-info.java")))
            .toList();

        assertTrue(missing.isEmpty(), () -> "Missing package boundaries: " + missing);
    }

    @Test
    void pureBoundariesDoNotReferenceGhidra() throws IOException {
        List<String> violations = new ArrayList<>();
        for (String boundary : PURE_BOUNDARIES) {
            violations.addAll(findGhidraReferences(MAIN_PACKAGE.resolve(boundary)));
        }

        assertTrue(violations.isEmpty(), () -> "Ghidra dependency outside adapter boundary: " + violations);
    }

    @Test
    void detectorRejectsForbiddenImportFixture() throws IOException {
        Path fixture = PROJECT_DIRECTORY.resolve(
            "src/test/resources/architecture/ForbiddenGhidraDependency.java.txt");

        List<String> violations = findGhidraReferences(fixture);

        assertEquals(1, violations.size(), "The negative fixture must exercise the architecture rule");
    }

    private static List<String> findGhidraReferences(Path path) throws IOException {
        if (!Files.exists(path)) {
            return List.of();
        }
        if (Files.isRegularFile(path)) {
            return scanFile(path);
        }
        try (Stream<Path> files = Files.walk(path)) {
            List<String> violations = new ArrayList<>();
            for (Path file : files.filter(Files::isRegularFile)
                .filter(candidate -> candidate.toString().endsWith(".java"))
                .sorted()
                .toList()) {
                violations.addAll(scanFile(file));
            }
            return List.copyOf(violations);
        }
    }

    private static List<String> scanFile(Path file) throws IOException {
        List<String> violations = new ArrayList<>();
        List<String> lines = Files.readAllLines(file, StandardCharsets.UTF_8);
        for (int index = 0; index < lines.size(); index++) {
            String line = lines.get(index);
            if (GHIDRA_IMPORT.matcher(line).find()
                || GHIDRA_QUALIFIED_REFERENCE.matcher(line).find()) {
                violations.add(PROJECT_DIRECTORY.relativize(file) + ":" + (index + 1));
            }
        }
        return List.copyOf(violations);
    }
}
