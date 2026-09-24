package io.github.rezabakhshi.embedra.analyzers.esp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.pack.RedistributionStatus;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import org.junit.jupiter.api.Test;

class Esp32S3FidProvenanceTest {
    private static final String SHA64_A =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    private static final String SHA64_B =
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    private static final String SHA64_C =
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    private static final String SHA64_D =
        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

    private static final String REVISION = "662a3be354759d9487bf4b1a629fadb766cb1800";

    @Test
    void validPilotDescriptorParsesAllEvidenceFields() throws Exception {
        Esp32S3FidProvenance parsed = parse(descriptorJson());

        assertEquals(Esp32S3FidProvenance.SCHEMA_ID, parsed.schemaId());
        assertEquals("esp32s3-esp-idf-v6.0-refapp-os", parsed.artifactId());
        assertEquals("esp32s3", parsed.targetId());
        assertEquals(9, parsed.chipId());
        assertEquals("Xtensa:LE:32:esp32s3", parsed.languageId());
        assertEquals("default", parsed.compilerSpecId());
        assertEquals("v6.0", parsed.idfVersion());
        assertEquals(REVISION, parsed.idfRevision());
        assertEquals("xtensa-esp-elf esp-15.2.0_20251204 (gcc 15.2.0)",
            parsed.toolchain());
        assertEquals("Os", parsed.optimization());
        assertEquals(SHA64_A, parsed.sdkconfigSha256());
        assertEquals(SHA64_B, parsed.referenceElfSha256());
        assertEquals(SHA64_C, parsed.strippedImageSha256());
        assertEquals(SHA64_D, parsed.fidbSha256());
        assertEquals(12, parsed.functionCount());
        assertEquals("./scripts/generate-esp32s3-fid-ref.sh build",
            parsed.generatorCommand());
        assertEquals("12.1.3", parsed.ghidraVersion());
        assertEquals("ESP-IDF", parsed.libraryFamily());
        assertEquals("v6.0", parsed.libraryVersion());
        assertEquals("esp32s3-Os", parsed.libraryVariant());
        assertEquals(RedistributionStatus.ALLOWED, parsed.redistribution());
        assertEquals(List.of("esp-idf/log", "esp-idf/esp_system", "embedra-pilot/main"),
            parsed.components().stream().map(Esp32S3FidComponent::name).toList());
        assertEquals("Apache-2.0", parsed.components().get(0).license());
        assertEquals(RedistributionStatus.ALLOWED, parsed.components().get(0).redistribution());
    }

    @Test
    void rejectsMissingOrUnknownKeys() {
        String missingKey = descriptorJson().replace(
            "  \"idfRevision\": \"662a3be354759d9487bf4b1a629fadb766cb1800\",\n", "");
        assertCode(DiagnosticCode.ESP_FID_PROVENANCE_INVALID, missingKey);

        String unknownKey = descriptorJson().replace("\"chipId\": 9,",
            "\"chipId\": 9, \"unexpected\": true,");
        assertCode(DiagnosticCode.ESP_FID_PROVENANCE_INVALID, unknownKey);
    }

    @Test
    void rejectsUnsupportedSchemaIdentity() {
        assertCode(DiagnosticCode.ESP_FID_PROVENANCE_SCHEMA_UNSUPPORTED,
            descriptorJson().replace(Esp32S3FidProvenance.SCHEMA_ID,
                "urn:embedra:schema:esp32s3-fidb-provenance:99"));
    }

    @Test
    void rejectsNonEsp32S3TargetLanguageOrChipVocabulary() {
        assertCode(DiagnosticCode.ESP_FID_PROVENANCE_INVALID,
            descriptorJson().replace("\"targetId\": \"esp32s3\",",
                "\"targetId\": \"esp32\","));
        assertCode(DiagnosticCode.ESP_FID_PROVENANCE_INVALID,
            descriptorJson().replace("\"languageId\": \"Xtensa:LE:32:esp32s3\",",
                "\"languageId\": \"Xtensa:LE:32:default\","));
        assertCode(DiagnosticCode.ESP_FID_PROVENANCE_INVALID,
            descriptorJson().replace("\"chipId\": 9,", "\"chipId\": 0,"));
    }

    @Test
    void rejectsMalformedDigestsRevisionOptimizationAndCounts() {
        assertCode(DiagnosticCode.ESP_FID_PROVENANCE_INVALID,
            descriptorJson().replace(SHA64_D, "deadbeef"));
        assertCode(DiagnosticCode.ESP_FID_PROVENANCE_INVALID,
            descriptorJson().replace("fidbSha256\": \"" + SHA64_D,
                "fidbSha256\": \"" + SHA64_D.toUpperCase(Locale.ROOT)));
        assertCode(DiagnosticCode.ESP_FID_PROVENANCE_INVALID,
            descriptorJson().replace(REVISION, "662a3be"));
        assertCode(DiagnosticCode.ESP_FID_PROVENANCE_INVALID,
            descriptorJson().replace("\"optimization\": \"Os\",",
                "\"optimization\": \"-Ofast\","));
        assertCode(DiagnosticCode.ESP_FID_PROVENANCE_INVALID,
            descriptorJson().replace("\"functionCount\": 12,", "\"functionCount\": 0,"));
    }

    @Test
    void rejectsEmptyComponentAuditAndConflictingRedistribution() {
        String emptyComponents = descriptorJson().replaceAll(
            "(?s)\"components\": \\[.*\\],", "\"components\": [],");
        assertCode(DiagnosticCode.ESP_FID_PROVENANCE_INVALID, emptyComponents);

        String restrictedComponent = descriptorJson().replace(
            "{\"name\": \"esp-idf/log\", \"license\": \"Apache-2.0\","
                + " \"redistribution\": \"ALLOWED\"}",
            "{\"name\": \"esp-idf/log\", \"license\": \"Proprietary\","
                + " \"redistribution\": \"PROHIBITED\"}");
        assertCode(DiagnosticCode.ESP_FID_PROVENANCE_INVALID, restrictedComponent);

        String unknownLicense = descriptorJson().replace(
            "\"license\": \"Apache-2.0\"", "\"license\": \"\"");
        assertCode(DiagnosticCode.ESP_FID_PROVENANCE_INVALID, unknownLicense);
    }

    @Test
    void rejectsHostPathsAndBlankCommands() {
        assertCode(DiagnosticCode.ESP_FID_PROVENANCE_INVALID,
            descriptorJson().replace("\"./scripts/generate-esp32s3-fid-ref.sh build\"",
                "\"/home/analyst/private/generate.sh\""));
        assertCode(DiagnosticCode.ESP_FID_PROVENANCE_INVALID,
            descriptorJson().replace("\"generatorCommand\": "
                + "\"./scripts/generate-esp32s3-fid-ref.sh build\"",
                "\"generatorCommand\": \"   \""));
    }

    @Test
    void enforcesInputLimitsAndCancellation() {
        byte[] json = descriptorJson().getBytes(StandardCharsets.UTF_8);
        CancellationToken cancelled = () -> true;
        assertCode(DiagnosticCode.CANCELLED, () ->
            Esp32S3FidProvenance.parse(json, ParserLimits.defaults(), cancelled));

        var tiny = ParserLimits.defaults().withMaxAllocationBytes(32);
        assertCode(DiagnosticCode.LIMIT_EXCEEDED, () ->
            Esp32S3FidProvenance.parse(json, tiny, CancellationToken.none()));
    }

    @Test
    void outcomeClassificationDistinguishesAppliedAmbiguousAndNoMatches() {
        Esp32S3FunctionIdOutcome applied = Esp32S3FunctionIdOutcome.classify(
            Esp32S3FunctionIdEvidence.CONFIRMED, 100, 5, 5, 0);
        assertEquals(Esp32S3FunctionIdStatus.MATCHES_APPLIED, applied.status());
        assertEquals(100, applied.functionsExamined());
        assertEquals(5, applied.functionsRenamed());
        assertEquals(0, applied.functionsAmbiguous());
        assertEquals(java.util.Optional.of(Esp32S3FunctionIdEvidence.CONFIRMED),
            applied.evidence());

        Esp32S3FunctionIdOutcome ambiguous = Esp32S3FunctionIdOutcome.classify(
            Esp32S3FunctionIdEvidence.UNCERTAIN, 100, 6, 4, 2);
        assertEquals(Esp32S3FunctionIdStatus.AMBIGUOUS_MATCHES, ambiguous.status());
        assertEquals(java.util.Optional.of(Esp32S3FunctionIdEvidence.UNCERTAIN),
            ambiguous.evidence());

        Esp32S3FunctionIdOutcome none = Esp32S3FunctionIdOutcome.classify(
            Esp32S3FunctionIdEvidence.CONFIRMED, 100, 0, 0, 0);
        assertEquals(Esp32S3FunctionIdStatus.NO_MATCHES, none.status());

        Esp32S3FunctionIdOutcome already = Esp32S3FunctionIdOutcome.classify(
            Esp32S3FunctionIdEvidence.CONFIRMED, 100, 3, 0, 0);
        assertEquals(Esp32S3FunctionIdStatus.ALREADY_APPLIED, already.status());

        Esp32S3FunctionIdOutcome refused = Esp32S3FunctionIdOutcome.refused(
            Esp32S3FunctionIdStatus.DATABASE_ABSENT);
        assertEquals(Esp32S3FunctionIdStatus.DATABASE_ABSENT, refused.status());
        assertEquals(0, refused.functionsRenamed());
        assertEquals(java.util.Optional.empty(), refused.evidence());

        assertThrows(IllegalArgumentException.class, () ->
            Esp32S3FunctionIdOutcome.classify(Esp32S3FunctionIdEvidence.CONFIRMED,
                -1, 0, 0, 0));
        assertThrows(IllegalArgumentException.class, () ->
            Esp32S3FunctionIdOutcome.classify(Esp32S3FunctionIdEvidence.CONFIRMED,
                2, 3, 0, 0));
        assertThrows(NullPointerException.class, () ->
            Esp32S3FunctionIdOutcome.refused(null));
        assertThrows(IllegalArgumentException.class, () ->
            Esp32S3FunctionIdOutcome.refused(Esp32S3FunctionIdStatus.MATCHES_APPLIED));
    }

    @Test
    void statusCodesAreStableMachineReadableTokens() {
        assertEquals("ESP32S3_FID_DATABASE_ABSENT",
            Esp32S3FunctionIdStatus.DATABASE_ABSENT.code());
        assertEquals("ESP32S3_FID_TARGET_INCOMPATIBLE",
            Esp32S3FunctionIdStatus.TARGET_INCOMPATIBLE.code());
        assertEquals("ESP32S3_FID_VERSION_INCOMPATIBLE",
            Esp32S3FunctionIdStatus.VERSION_INCOMPATIBLE.code());
        assertEquals("ESP32S3_FID_DATABASE_DIGEST_MISMATCH",
            Esp32S3FunctionIdStatus.DATABASE_DIGEST_MISMATCH.code());
        assertEquals("ESP32S3_FID_PROVENANCE_INVALID",
            Esp32S3FunctionIdStatus.PROVENANCE_INVALID.code());
        assertEquals("ESP32S3_FID_AMBIGUOUS_MATCHES",
            Esp32S3FunctionIdStatus.AMBIGUOUS_MATCHES.code());
        assertEquals("ESP32S3_FID_MATCHES_APPLIED",
            Esp32S3FunctionIdStatus.MATCHES_APPLIED.code());
        assertEquals("ESP32S3_FID_NO_MATCHES",
            Esp32S3FunctionIdStatus.NO_MATCHES.code());
        assertEquals("ESP32S3_FID_CANCELLED",
            Esp32S3FunctionIdStatus.CANCELLED.code());
        assertEquals("ESP32S3_FID_RUN_FAILED",
            Esp32S3FunctionIdStatus.RUN_FAILED.code());
        List<String> codes = Arrays.stream(Esp32S3FunctionIdStatus.values())
            .map(Esp32S3FunctionIdStatus::code).toList();
        assertEquals(codes.size(), new HashSet<>(codes).size());
        assertTrue(codes.stream().allMatch(code -> code.startsWith("ESP32S3_FID_")));
    }

    private static Esp32S3FidProvenance parse(String json) throws DiagnosticException {
        return Esp32S3FidProvenance.parse(json.getBytes(StandardCharsets.UTF_8),
            ParserLimits.defaults(), CancellationToken.none());
    }

    private static void assertCode(DiagnosticCode expected, String json) {
        DiagnosticException thrown = assertThrows(DiagnosticException.class,
            () -> parse(json));
        assertEquals(expected, thrown.diagnostic().code());
    }

    private static void assertCode(DiagnosticCode expected, ThrowingCall call) {
        DiagnosticException thrown = assertThrows(DiagnosticException.class, call::run);
        assertEquals(expected, thrown.diagnostic().code());
    }

    private interface ThrowingCall {
        void run() throws Exception;
    }

    private static String descriptorJson() {
        return """
            {
              "schemaId": "urn:embedra:schema:esp32s3-fidb-provenance:1",
              "artifactId": "esp32s3-esp-idf-v6.0-refapp-os",
              "targetId": "esp32s3",
              "chipId": 9,
              "languageId": "Xtensa:LE:32:esp32s3",
              "compilerSpecId": "default",
              "idfVersion": "v6.0",
              "idfRevision": "662a3be354759d9487bf4b1a629fadb766cb1800",
              "toolchain": "xtensa-esp-elf esp-15.2.0_20251204 (gcc 15.2.0)",
              "optimization": "Os",
              "sdkconfigSha256": "%s",
              "referenceElfSha256": "%s",
              "strippedImageSha256": "%s",
              "fidbSha256": "%s",
              "functionCount": 12,
              "generatorCommand": "./scripts/generate-esp32s3-fid-ref.sh build",
              "ghidraVersion": "12.1.3",
              "libraryFamily": "ESP-IDF",
              "libraryVersion": "v6.0",
              "libraryVariant": "esp32s3-Os",
              "components": [
                {"name": "esp-idf/log", "license": "Apache-2.0", "redistribution": "ALLOWED"},
                {"name": "esp-idf/esp_system", "license": "Apache-2.0", "redistribution": "ALLOWED"},
                {"name": "embedra-pilot/main", "license": "Apache-2.0", "redistribution": "ALLOWED"}
              ],
              "redistribution": "ALLOWED"
            }
            """.formatted(SHA64_A, SHA64_B, SHA64_C, SHA64_D);
    }
}
