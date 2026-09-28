package io.github.rezabakhshi.embedra.targets.esp.catalog;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.CancellationSource;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.catalog.SupportState;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class EspDeviceCatalogTest {
    private static final Path CATALOG = Path.of("catalogs", "espressif", "2026-09-23");

    private static final Set<String> REQUIRED_SERIES = Set.of(
        "ESP32", "ESP32-S2", "ESP32-S3", "ESP32-S31", "ESP32-P4", "ESP32-C2",
        "ESP32-C3", "ESP32-C5", "ESP32-C6", "ESP32-C61", "ESP32-E22",
        "ESP32-H2", "ESP32-H21", "ESP32-H4");

    @TempDir
    Path temporaryDirectory;

    @Test
    void loadsPinnedCompleteOfficialSnapshotWithoutPromotingSupport() throws Exception {
        EspDeviceCatalog catalog = load(CATALOG);

        assertEquals(REQUIRED_SERIES, catalog.silicon().stream()
            .map(EspCatalogRecord::series).collect(Collectors.toSet()));
        assertTrue(catalog.silicon().size() >= 50);
        assertTrue(catalog.modules().size() >= 140);
        assertTrue(catalog.boards().size() >= 40);
        assertFalse(catalog.records().stream()
            .anyMatch(record -> record.exactPart().startsWith("ESP8266")));
        assertTrue(catalog.records().stream().allMatch(record ->
            record.supportStates().values().stream().allMatch(state -> state == SupportState.PLANNED)));

        EspCatalogRecord s3 = catalog.requireExactPart("ESP32-S3FN8");
        assertEquals(EspCatalogEntityKind.SILICON, s3.kind());
        assertEquals(EspCpuIsa.XTENSA, s3.isa());
        assertEquals(2, s3.applicationCoreCount());
        assertEquals("8", s3.embeddedFlashMb());
        assertEquals("QFN 7x7", s3.packageName());
        assertTrue(s3.peripheralCapabilities().contains("SOC_USB_OTG_SUPPORTED"));
        assertTrue(s3.securityCapabilities().contains("SOC_AES_SUPPORTED"));
        assertEquals("UNKNOWN", s3.romIdentity());
        assertEquals(53, catalog.deviceSnapshot().devices().size());
        assertEquals(catalog.sourceFactsSha256(),
            catalog.deviceSnapshot().source().revision());
    }

    @Test
    void profilesReferenceCatalogedSiliconAndNeverBecomeProcessorModels() throws Exception {
        EspDeviceCatalog catalog = load(CATALOG);
        Set<String> siliconIds = catalog.silicon().stream()
            .map(EspCatalogRecord::recordId).collect(Collectors.toSet());

        assertTrue(catalog.modules().stream().allMatch(profile ->
            !profile.siliconRecordIds().isEmpty()
                && siliconIds.containsAll(profile.siliconRecordIds())));
        assertTrue(catalog.boards().stream().allMatch(profile ->
            !profile.siliconRecordIds().isEmpty()
                && siliconIds.containsAll(profile.siliconRecordIds())));
        assertFalse(catalog.silicon().stream()
            .anyMatch(record -> record.exactPart().contains("DevKit")
                || record.exactPart().contains("WROOM")));
    }

    @Test
    void resolverSeparatesExactAmbiguousAndUnknownQueries() throws Exception {
        EspDeviceCatalog catalog = load(CATALOG);

        EspCatalogResolution exact = catalog.resolve("ESP32-S3FN8");
        assertEquals(EspCatalogResolutionStatus.EXACT, exact.status());
        assertEquals("ESP32-S3FN8", exact.requireExact().exactPart());

        EspCatalogResolution ambiguous = catalog.resolve("ESP32-S3-WROOM-1");
        assertEquals(EspCatalogResolutionStatus.AMBIGUOUS, ambiguous.status());
        assertTrue(ambiguous.candidates().size() > 1);
        assertThrows(IllegalStateException.class, ambiguous::requireExact);

        EspCatalogResolution unknown = catalog.resolve("not-an-espressif-product");
        assertEquals(EspCatalogResolutionStatus.UNKNOWN, unknown.status());
        assertTrue(unknown.candidates().isEmpty());
    }

    @Test
    void typedProfileResolutionNeverPromotesModulesOrBoardsToSilicon() throws Exception {
        EspDeviceCatalog catalog = load(CATALOG);

        EspCatalogRecord module = catalog.resolveModule("ESP32-C3-MINI-1-H4")
            .requireExact();
        EspCatalogRecord board = catalog.resolveBoard("ESP32-C3-DevKitM-1-N4X")
            .requireExact();
        assertEquals(EspCatalogEntityKind.MODULE, module.kind());
        assertEquals(EspCatalogEntityKind.BOARD, board.kind());
        assertEquals(EspCatalogResolutionStatus.UNKNOWN,
            catalog.resolveSilicon(module.exactPart()).status());
        assertThrows(IllegalStateException.class,
            () -> catalog.requireExactSilicon(module.exactPart()));

        List<EspCatalogRecord> compatible = catalog.compatibleSilicon(module);
        assertFalse(compatible.isEmpty());
        assertTrue(compatible.stream().allMatch(record ->
            record.kind() == EspCatalogEntityKind.SILICON));
        assertTrue(compatible.stream().anyMatch(record ->
            record.exactPart().equals("ESP32-C3FH4")));
        assertThrows(IllegalArgumentException.class,
            () -> catalog.compatibleSilicon(compatible.getFirst()));

        List<EspCatalogRecord> profiles = catalog.profilesForSilicon("ESP32-C3FH4");
        assertTrue(profiles.contains(module));
        assertTrue(profiles.stream().noneMatch(record ->
            record.kind() == EspCatalogEntityKind.SILICON));
        assertTrue(catalog.profilesForSilicon("ESP32-C3").contains(board));
        assertEquals(EspCatalogEntityKind.MODULE,
            catalog.resolveProfile(module.exactPart()).requireExact().kind());
    }

    @Test
    void retainsDistinctIsaTopologyAndAuxiliaryProcessorEvidence() throws Exception {
        EspDeviceCatalog catalog = load(CATALOG);

        assertEquals(EspCpuIsa.XTENSA,
            catalog.requireExactPart("ESP32-D0WD-V3").isa());
        assertEquals(EspCpuIsa.RISCV,
            catalog.requireExactPart("ESP32-C3").isa());
        assertEquals(2, catalog.requireExactPart("ESP32-S31NRV16").applicationCoreCount());
        assertTrue(catalog.requireExactPart("ESP32-P4NRW16").auxiliaryProcessors()
            .contains("LP_RISCV"));
        assertTrue(catalog.requireExactPart("ESP32-S3").auxiliaryProcessors()
            .contains("ULP_RISCV"));
    }

    @Test
    void rejectsTamperingLimitsCancellationAndMalformedRelationships() throws Exception {
        Path copy = temporaryDirectory.resolve("catalog");
        copyTree(CATALOG, copy);
        Files.writeString(copy.resolve("catalog.json"), "tampered");
        DiagnosticException tampered = assertThrows(DiagnosticException.class,
            () -> load(copy));
        assertEquals(DiagnosticCode.ESP_CATALOG_INTEGRITY_MISMATCH,
            tampered.diagnostic().code());

        ParserLimits tiny = new ParserLimits(128, 128, 128, 8, 4,
            ParserLimits.defaults().maxWallTime());
        DiagnosticException limited = assertThrows(DiagnosticException.class,
            () -> EspDeviceCatalogLoader.load(CATALOG, tiny, CancellationToken.none()));
        assertEquals(DiagnosticCode.LIMIT_EXCEEDED, limited.diagnostic().code());

        CancellationSource cancellation = new CancellationSource();
        cancellation.cancel();
        DiagnosticException cancelled = assertThrows(DiagnosticException.class,
            () -> EspDeviceCatalogLoader.load(CATALOG, ParserLimits.defaults(),
                cancellation.token()));
        assertEquals(DiagnosticCode.CANCELLED, cancelled.diagnostic().code());

        Path malformed = temporaryDirectory.resolve("malformed");
        Files.createDirectories(malformed);
        Files.writeString(malformed.resolve("catalog.json"),
            "{\"schemaId\":\"urn:embedra:schema:esp-device-catalog:1\","
                + "\"catalogId\":\"bad\",\"sources\":[],\"records\":[]}");
        Files.writeString(malformed.resolve("catalog.sha256"),
            EspCatalogTestSupport.sha256(malformed.resolve("catalog.json")) + "  catalog.json\n");
        DiagnosticException invalid = assertThrows(DiagnosticException.class,
            () -> load(malformed));
        assertEquals(DiagnosticCode.ESP_CATALOG_INVALID, invalid.diagnostic().code());
    }

    @Test
    void modelsRejectInconsistentTopologyResolutionAndProvenance() {
        Map<String, SupportState> states = Map.of("catalog", SupportState.PLANNED);
        assertThrows(IllegalArgumentException.class, () -> new EspCatalogRecord(
            "silicon:test", EspCatalogEntityKind.SILICON, "ESP32-X", "ESP32-X",
            "QFN", EspCpuIsa.PROFILE, 1, List.of(), "N/A", "N/A", "ACTIVE",
            "UNSPECIFIED", "UNKNOWN", "UNKNOWN", "test", List.of(), List.of(),
            List.of(), List.of(), states));
        assertThrows(IllegalArgumentException.class, () -> new EspCatalogRecord(
            "module:test", EspCatalogEntityKind.MODULE, "ESP32-X", "ESP32-X-MOD",
            "MODULE", EspCpuIsa.PROFILE, 0, List.of(), "4", "N/A", "ACTIVE",
            "PROFILE", "PROFILE", "PROFILE", "profile", List.of(), List.of(),
            List.of(), List.of(), states));
        assertThrows(IllegalArgumentException.class, () -> new EspCatalogSource(
            "source", "https://example.invalid", "revision", "not-a-digest",
            "license", "ALLOWED"));
        assertThrows(IllegalArgumentException.class, () -> new EspCatalogResolution(
            EspCatalogResolutionStatus.EXACT, "query", List.of()));
        assertThrows(IllegalArgumentException.class, () -> new EspCatalogResolution(
            EspCatalogResolutionStatus.UNKNOWN, "query", List.of(new EspCatalogRecord(
                "silicon:test", EspCatalogEntityKind.SILICON, "ESP32-X", "ESP32-X",
                "QFN", EspCpuIsa.RISCV, 1, List.of(), "N/A", "N/A", "ACTIVE",
                "UNSPECIFIED", "UNKNOWN", "UNKNOWN", "test", List.of(), List.of(),
                List.of(), List.of(), states))));
    }

    private static EspDeviceCatalog load(Path path) throws DiagnosticException {
        return EspDeviceCatalogLoader.load(path, ParserLimits.defaults(),
            CancellationToken.none());
    }

    private static void copyTree(Path source, Path destination) throws Exception {
        try (var paths = Files.walk(source)) {
            for (Path path : paths.toList()) {
                Path target = destination.resolve(source.relativize(path).toString());
                if (Files.isDirectory(path)) {
                    Files.createDirectories(target);
                }
                else {
                    Files.copy(path, target);
                }
            }
        }
    }
}
