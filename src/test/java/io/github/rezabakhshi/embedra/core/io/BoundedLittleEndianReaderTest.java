package io.github.rezabakhshi.embedra.core.io;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import org.junit.jupiter.api.Test;

class BoundedLittleEndianReaderTest {
    private static final byte[] SAMPLE = {
        0x01, 0x23, 0x45, 0x67, (byte) 0x89, (byte) 0xab, (byte) 0xcd, (byte) 0xef
    };

    @Test
    void readsUnsignedLittleEndianValuesWithinItsSourceRange() throws DiagnosticException {
        BoundedLittleEndianReader reader = new BoundedLittleEndianReader(
            SAMPLE, new SourceRange(1, 7), ParserLimits.defaults(), CancellationToken.none());

        assertEquals(1, reader.sourcePosition());
        assertEquals(0x4523, reader.readUnsignedShort());
        assertEquals(0xcdab8967L, reader.readUnsignedInt());
        assertEquals(7, reader.sourcePosition());
        assertEquals(1, reader.remaining());
        assertArrayEquals(new byte[] {(byte) 0xef}, reader.readBytes(1));
    }

    @Test
    void reportsTypedTruncationWithoutMovingTheCursor() throws DiagnosticException {
        BoundedLittleEndianReader reader = new BoundedLittleEndianReader(
            SAMPLE, new SourceRange(6, 2), ParserLimits.defaults(), CancellationToken.none());

        DiagnosticException failure = assertThrows(DiagnosticException.class, reader::readUnsignedInt);

        assertEquals(DiagnosticCode.READ_OUT_OF_BOUNDS, failure.diagnostic().code());
        assertEquals(6, reader.sourcePosition());
    }

    @Test
    void rejectsRangesOutsideTheInputAndOversizedAllocations() {
        assertThrows(IllegalArgumentException.class, () -> new BoundedLittleEndianReader(
            SAMPLE, new SourceRange(7, 2), ParserLimits.defaults(), CancellationToken.none()));

        ParserLimits limits = ParserLimits.defaults().withMaxAllocationBytes(2);
        BoundedLittleEndianReader reader = new BoundedLittleEndianReader(
            SAMPLE, new SourceRange(0, SAMPLE.length), limits, CancellationToken.none());
        DiagnosticException failure = assertThrows(DiagnosticException.class, () -> reader.readBytes(3));

        assertEquals(DiagnosticCode.LIMIT_EXCEEDED, failure.diagnostic().code());
        assertEquals(0, reader.sourcePosition());
    }

    @Test
    void supportsCheckedSkippingAndUnsignedByteReads() throws DiagnosticException {
        BoundedLittleEndianReader reader = new BoundedLittleEndianReader(
            SAMPLE, new SourceRange(0, SAMPLE.length), ParserLimits.defaults(), CancellationToken.none());

        reader.skip(3);

        assertEquals(0x67, reader.readUnsignedByte());
        assertThrows(IllegalArgumentException.class, () -> reader.skip(-1));
    }

    @Test
    void readsLittleEndianLongAndRejectsNegativeReads() throws DiagnosticException {
        BoundedLittleEndianReader reader = new BoundedLittleEndianReader(
            SAMPLE, new SourceRange(0, SAMPLE.length), ParserLimits.defaults(), CancellationToken.none());

        assertEquals(0xefcdab8967452301L, reader.readLong());
        assertThrows(IllegalArgumentException.class, () -> reader.readBytes(-1));
    }

    @Test
    void rejectsInputBeyondConfiguredLimit() {
        ParserLimits limits = new ParserLimits(4, 4, 4, 1, 1, java.time.Duration.ofSeconds(1));

        assertThrows(IllegalArgumentException.class, () -> new BoundedLittleEndianReader(
            SAMPLE, new SourceRange(0, SAMPLE.length), limits, CancellationToken.none()));
    }
}
