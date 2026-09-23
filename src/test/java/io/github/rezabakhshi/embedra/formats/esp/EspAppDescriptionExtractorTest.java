package io.github.rezabakhshi.embedra.formats.esp;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticSeverity;
import io.github.rezabakhshi.embedra.core.io.SourceRange;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

class EspAppDescriptionExtractorTest {
    private static final String FIXTURE =
        "/fixtures/esp32s3/esp32s3-freestanding-minimal.bin";

    private static final int ESP32_S3_CHIP_ID = 9;

    @Test
    void extractsExactBoundedMetadataAndProvenanceFromGoldenImage() throws Exception {
        EspAppDescriptionResult result = EspAppDescriptionExtractor.extract(goldenImage());

        assertTrue(result.diagnostics().isEmpty());
        EspAppDescription description = result.description().orElseThrow();
        assertEquals(0xabcd5432L, description.magic());
        assertEquals(0, description.secureVersion());
        assertEquals("1.0.0", description.version());
        assertEquals("embedra_t008_fixture", description.projectName());
        assertEquals("", description.buildTime());
        assertEquals("", description.buildDate());
        assertEquals("fixture-no-idf-runtime", description.idfVersion());
        assertArrayEquals(new byte[32], description.appElfSha256());
        assertEquals(0, description.minimumEfuseBlockRevision());
        assertEquals(199, description.maximumEfuseBlockRevision());
        assertEquals(65_536L, description.mmuPageSizeBytes());
        assertEquals(0x3c010020L, description.targetAddress());
        assertEquals(new SourceRange(32, 256), description.sourceRange());

        byte[] digest = description.appElfSha256();
        digest[0] = 1;
        assertArrayEquals(new byte[32], description.appElfSha256());
    }

    @Test
    void returnsNoMetadataOrDiagnosticWhenDescriptorIsAbsent() throws Exception {
        EspImage image = withFirstSegmentMutation(data -> {
            data[0] = 0;
            data[1] = 0;
            data[2] = 0;
            data[3] = 0;
            return data;
        });

        EspAppDescriptionResult result = EspAppDescriptionExtractor.extract(image);

        assertTrue(result.description().isEmpty());
        assertTrue(result.diagnostics().isEmpty());
    }

    @Test
    void reportsTruncatedDescriptorWithoutInvalidatingTheParsedImage() throws Exception {
        EspImage image = withFirstSegmentMutation(data -> java.util.Arrays.copyOf(data, 100));

        EspAppDescriptionResult result = EspAppDescriptionExtractor.extract(image);

        assertTrue(result.description().isEmpty());
        assertEquals(1, result.diagnostics().size());
        assertEquals(DiagnosticCode.ESP_APP_DESC_TRUNCATED,
            result.diagnostics().get(0).code());
        assertEquals(DiagnosticSeverity.WARNING, result.diagnostics().get(0).severity());
        assertEquals(new SourceRange(32, 100),
            result.diagnostics().get(0).sourceRange().orElseThrow());
        assertEquals(3, image.segments().size());
    }

    @Test
    void rejectsInvalidBoundedTextAsNonFatalOptionalMetadata() throws Exception {
        EspImage image = withFirstSegmentMutation(data -> {
            data[16] = 1;
            return data;
        });

        EspAppDescriptionResult result = EspAppDescriptionExtractor.extract(image);

        assertTrue(result.description().isEmpty());
        assertEquals(DiagnosticCode.ESP_APP_DESC_INVALID,
            result.diagnostics().get(0).code());
        assertEquals(DiagnosticSeverity.WARNING, result.diagnostics().get(0).severity());
        assertFalse(image.segments().isEmpty());
    }

    private static EspImage withFirstSegmentMutation(SegmentMutation mutation) throws Exception {
        EspImage image = goldenImage();
        List<EspImageSegment> segments = new ArrayList<>(image.segments());
        EspImageSegment original = segments.get(0);
        byte[] mutated = mutation.apply(original.data());
        segments.set(0, new EspImageSegment(original.index(), original.loadAddress(), mutated,
            original.headerSourceRange(),
            new SourceRange(original.dataSourceRange().offset(), mutated.length)));
        return new EspImage(image.header(), segments, image.footer(), image.sourceRange());
    }

    private static EspImage goldenImage() throws Exception {
        return EspImageParser.parseForChip(fixture(), ESP32_S3_CHIP_ID,
            ParserLimits.defaults(), CancellationToken.none());
    }

    private static byte[] fixture() throws IOException {
        try (InputStream input = EspAppDescriptionExtractorTest.class.getResourceAsStream(FIXTURE)) {
            assertTrue(input != null, "missing fixture " + FIXTURE);
            return input.readAllBytes();
        }
    }

    @FunctionalInterface
    private interface SegmentMutation {
        byte[] apply(byte[] data);
    }
}
