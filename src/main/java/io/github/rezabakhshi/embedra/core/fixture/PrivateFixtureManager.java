package io.github.rezabakhshi.embedra.core.fixture;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Stream;

/**
 * Manages private and non-redistributable firmware fixtures under strict provenance isolation (SPEC-12, SPEC-13).
 */
public final class PrivateFixtureManager {

    /** Built-in T021 local flash dump fixture ID. */
    public static final String T021_DUMP_FIXTURE_ID = "esp32s3.restricted-local.4mb-flash-capture";

    /** Pinned SHA-256 for the T021 4 MiB dump. */
    public static final String T021_DUMP_SHA256 =
            "837ee155de84403f84330179d52edfd2dba239cc11af5e55c2d0c28bc38a71de";

    private final Map<String, PrivateFixtureDescriptor> registeredFixtures = new LinkedHashMap<>();

    public PrivateFixtureManager() {
        // Register known specification-defined private/restricted fixtures
        register(new PrivateFixtureDescriptor(
                T021_DUMP_FIXTURE_ID,
                T021_DUMP_SHA256,
                "ESP32-S3",
                "fixtures/restricted/esp32s3-4mb-flash-capture.bin",
                "User-supplied 4 MiB flash capture excluded by .gitignore",
                RedistributionStatus.RESTRICTED_LOCAL));
    }

    public void register(PrivateFixtureDescriptor descriptor) {
        Objects.requireNonNull(descriptor, "descriptor");
        registeredFixtures.put(descriptor.fixtureId(), descriptor);
    }

    public Optional<PrivateFixtureDescriptor> getDescriptor(String fixtureId) {
        return Optional.ofNullable(registeredFixtures.get(fixtureId));
    }

    public Map<String, PrivateFixtureDescriptor> allDescriptors() {
        return Collections.unmodifiableMap(registeredFixtures);
    }

    /**
     * Resolves a private fixture file on the local machine if present, verifying digest and isolation.
     *
     * @param fixtureId registered fixture ID
     * @param projectRoot project base directory
     * @return path to verified binary, or empty if not present locally
     * @throws DiagnosticException if file is invalid, digest mismatches, or repository boundary is violated
     */
    public Optional<Path> resolvePrivateFixture(
            String fixtureId,
            Path projectRoot) throws DiagnosticException, IOException {
        PrivateFixtureDescriptor descriptor = registeredFixtures.get(fixtureId);
        if (descriptor == null) {
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.FIXTURE_MANIFEST_INVALID,
                    "Unknown private fixture ID: " + fixtureId));
        }

        Path candidate = null;
        String propDir = System.getProperty("embedra.private.fixtures.dir");
        if (propDir != null && !propDir.isBlank()) {
            Path p = Path.of(propDir).resolve(Path.of(descriptor.relativePath()).getFileName());
            if (Files.exists(p)) {
                candidate = p;
            }
        }
        if (candidate == null && projectRoot != null) {
            Path p = projectRoot.resolve(descriptor.relativePath());
            if (Files.exists(p)) {
                candidate = p;
            }
        }

        if (candidate == null) {
            return Optional.empty();
        }

        // Enforce safety: no symlink, must be regular file
        if (Files.isSymbolicLink(candidate)) {
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.FIXTURE_PATH_UNSAFE,
                    "Private fixture must not be a symbolic link: " + candidate));
        }
        if (!Files.isRegularFile(candidate)) {
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.FIXTURE_PATH_UNSAFE,
                    "Private fixture must be a regular file: " + candidate));
        }

        // Enforce boundary: never allow private fixture in public redistributable fixture tree
        if (projectRoot != null) {
            Path redistributableTree = projectRoot.resolve("src/test/resources/fixtures");
            if (candidate.toAbsolutePath().normalize().startsWith(redistributableTree.toAbsolutePath().normalize())) {
                throw new DiagnosticException(Diagnostic.error(
                        DiagnosticCode.FIXTURE_REDISTRIBUTION_INVALID,
                        "Private fixture is inside the public redistributable fixture directory: " + candidate));
            }
        }

        // Enforce bit-for-bit digest integrity
        byte[] bytes = Files.readAllBytes(candidate);
        String actualSha256 = FixtureManifest.computeSha256(bytes);
        if (!actualSha256.equalsIgnoreCase(descriptor.expectedSha256())) {
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.FIXTURE_INTEGRITY_MISMATCH,
                    "Private fixture digest mismatch for " + fixtureId + ": expected "
                            + descriptor.expectedSha256() + ", got " + actualSha256));
        }

        return Optional.of(candidate);
    }

    /**
     * Audits the public fixture tree to guarantee no private/restricted fixtures are checked in.
     *
     * @param publicFixtureTree path to src/test/resources/fixtures
     * @throws DiagnosticException if any non-redistributable fixture is found
     */
    public void auditPublicFixtureTree(Path publicFixtureTree) throws DiagnosticException, IOException {
        if (!Files.isDirectory(publicFixtureTree)) {
            return;
        }

        ParserLimits limits = ParserLimits.defaults();
        CancellationToken token = CancellationToken.none();

        try (Stream<Path> stream = Files.walk(publicFixtureTree)) {
            for (Path manifestPath : stream.filter(p -> p.toString().endsWith(".manifest.json")).toList()) {
                FixtureManifest manifest = FixtureManifest.read(manifestPath, limits, token);
                if (manifest.redistributionStatus() != RedistributionStatus.REDISTRIBUTABLE) {
                    throw new DiagnosticException(Diagnostic.error(
                            DiagnosticCode.FIXTURE_REDISTRIBUTION_INVALID,
                            "Public fixture directory contains non-redistributable manifest: "
                                    + manifestPath + " (status=" + manifest.redistributionStatus() + ")"));
                }
            }
        }
    }

    /**
     * Immutable descriptor for private fixture metadata.
     */
    public record PrivateFixtureDescriptor(
            String fixtureId,
            String expectedSha256,
            String target,
            String relativePath,
            String description,
            RedistributionStatus redistributionStatus) {

        public PrivateFixtureDescriptor {
            Objects.requireNonNull(fixtureId, "fixtureId");
            Objects.requireNonNull(expectedSha256, "expectedSha256");
            Objects.requireNonNull(target, "target");
            Objects.requireNonNull(relativePath, "relativePath");
            Objects.requireNonNull(description, "description");
            Objects.requireNonNull(redistributionStatus, "redistributionStatus");
            if (redistributionStatus == RedistributionStatus.REDISTRIBUTABLE) {
                throw new IllegalArgumentException("Private fixture descriptor cannot be REDISTRIBUTABLE");
            }
        }
    }
}
