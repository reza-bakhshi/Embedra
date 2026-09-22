package io.github.rezabakhshi.embedra.formats.esp;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.io.SourceRange;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import org.junit.jupiter.api.Test;

class EspImageDetectorParserTest {
    private static final String FIXTURE_ROOT = "/fixtures/esp32s3/";

    private static final int ESP32_S3_CHIP_ID = 9;

    @Test
    void detectorDistinguishesNonImagesCandidatesAndStructurallyValidHeaders()
            throws IOException {
        byte[] valid = fixture("esp32s3-freestanding-minimal.bin");

        assertEquals(EspImageDetection.MATCH, EspImageDetector.detect(valid));
        assertEquals(EspImageDetection.NO_MATCH,
            EspImageDetector.detect(new byte[] {0x45, 0x4d, 0x42, 0x52}));
        assertEquals(EspImageDetection.MALFORMED,
            EspImageDetector.detect(new byte[] {(byte) 0xe9, 3, 2}));

        byte[] invalidSegmentCount = valid.clone();
        invalidSegmentCount[1] = 17;
        assertEquals(EspImageDetection.MALFORMED,
            EspImageDetector.detect(invalidSegmentCount));

        byte[] invalidDigestFlag = valid.clone();
        invalidDigestFlag[23] = 2;
        assertEquals(EspImageDetection.MALFORMED,
            EspImageDetector.detect(invalidDigestFlag));
    }

    @Test
    void parserPreservesExactHeaderSegmentsFooterAndSourceRanges() throws Exception {
        byte[] input = fixture("esp32s3-freestanding-minimal.bin");
        EspImage image = EspImageParser.parseForChip(input, ESP32_S3_CHIP_ID,
            ParserLimits.defaults(), CancellationToken.none());

        EspImageHeader header = image.header();
        assertEquals(0xe9, header.magic());
        assertEquals(3, header.segmentCount());
        assertEquals(2, header.flashMode());
        assertEquals(0x10, header.flashSizeFrequency());
        assertEquals(0x4037_8008L, header.entryPoint());
        assertEquals(0xee, header.writeProtectPin());
        assertEquals(0, header.clockDriveStrength());
        assertEquals(0, header.qDriveStrength());
        assertEquals(0, header.dDriveStrength());
        assertEquals(0, header.csDriveStrength());
        assertEquals(0, header.hdDriveStrength());
        assertEquals(0, header.wpDriveStrength());
        assertEquals(ESP32_S3_CHIP_ID, header.chipId());
        assertEquals(0, header.minimumRevision());
        assertEquals(0, header.minimumRevisionFull());
        assertEquals(0xffff, header.maximumRevisionFull());
        assertTrue(header.digestAppended());
        assertEquals(new SourceRange(0, 24), header.sourceRange());

        List<EspImageSegment> segments = image.segments();
        assertEquals(3, segments.size());
        assertSegment(segments.get(0), 0, 0x3c01_0020L, 296, 24, 32);
        assertSegment(segments.get(1), 1, 0x3fc8_8000L, 4, 328, 336);
        assertSegment(segments.get(2), 2, 0x4037_8000L, 36, 340, 348);

        EspImageFooter footer = image.footer();
        assertEquals(new SourceRange(384, 15), footer.paddingSourceRange());
        assertArrayEquals(new byte[15], footer.padding());
        assertEquals(0x5d, footer.storedChecksum());
        assertEquals(0x5d, footer.calculatedChecksum());
        assertTrue(footer.checksumValid());
        assertEquals(new SourceRange(399, 1), footer.checksumSourceRange());
        assertTrue(footer.digestPresent());
        assertTrue(footer.digestValid());
        assertEquals(new SourceRange(400, 32), footer.digestSourceRange().orElseThrow());
        assertArrayEquals(footer.storedDigest(), footer.calculatedDigest());
        assertEquals(new SourceRange(0, 432), image.sourceRange());
    }

    @Test
    void parserSupportsImagesWithoutAnAppendedDigest() throws Exception {
        EspImage image = EspImageParser.parseForChip(
            fixture("esp32s3-freestanding-minimal-no-digest.bin"), ESP32_S3_CHIP_ID,
            ParserLimits.defaults(), CancellationToken.none());

        assertFalse(image.header().digestAppended());
        assertFalse(image.footer().digestPresent());
        assertFalse(image.footer().digestSourceRange().isPresent());
        assertArrayEquals(new byte[0], image.footer().storedDigest());
        assertArrayEquals(new byte[0], image.footer().calculatedDigest());
        assertEquals(new SourceRange(0, 400), image.sourceRange());
    }

    @Test
    void parsedModelOwnsImmutableCopiesOfInputCollectionsAndArrays() throws Exception {
        byte[] input = fixture("esp32s3-freestanding-minimal.bin");
        EspImage image = EspImageParser.parseForChip(input, ESP32_S3_CHIP_ID,
            ParserLimits.defaults(), CancellationToken.none());
        byte original = image.segments().get(0).data()[0];

        input[32] ^= 0x7f;
        byte[] segmentData = image.segments().get(0).data();
        segmentData[0] ^= 0x7f;
        byte[] digest = image.footer().storedDigest();
        digest[0] ^= 0x7f;

        assertEquals(original, image.segments().get(0).data()[0]);
        assertFalse(digest[0] == image.footer().storedDigest()[0]);
        assertFalse(segmentData[0] == image.segments().get(0).data()[0]);
        assertThrowsUnsupported(() -> image.segments().add(image.segments().get(0)));
    }

    private static void assertSegment(EspImageSegment segment, int index, long address,
            int length, long headerOffset, long dataOffset) {
        assertEquals(index, segment.index());
        assertEquals(address, segment.loadAddress());
        assertEquals(length, segment.length());
        assertEquals(new SourceRange(headerOffset, 8), segment.headerSourceRange());
        assertEquals(new SourceRange(dataOffset, length), segment.dataSourceRange());
        assertEquals(address, segment.targetRange().start());
        assertEquals(length, segment.targetRange().length());
    }

    private static void assertThrowsUnsupported(Runnable operation) {
        boolean thrown = false;
        try {
            operation.run();
        }
        catch (UnsupportedOperationException expected) {
            thrown = true;
        }
        assertTrue(thrown, "collection mutation must be rejected");
    }

    private static byte[] fixture(String name) throws IOException {
        try (InputStream input = EspImageDetectorParserTest.class.getResourceAsStream(
                FIXTURE_ROOT + name)) {
            assertTrue(input != null, "missing fixture " + name);
            return input.readAllBytes();
        }
    }
}
