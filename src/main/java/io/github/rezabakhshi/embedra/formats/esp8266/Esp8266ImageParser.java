package io.github.rezabakhshi.embedra.formats.esp8266;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.core.io.BoundedLittleEndianReader;
import io.github.rezabakhshi.embedra.core.io.SourceRange;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.OptionalLong;
import java.util.zip.CRC32;

/** Bounded parser for the independent ESP8266 version 1 and version 2 formats. */
public final class Esp8266ImageParser {
    private static final int SEGMENT_HEADER_LENGTH = 8;

    private static final long MAX_SEGMENT_LENGTH = 0x0100_0000L;

    private static final int CHECKSUM_SEED = 0xef;

    private static final int SDK_CRC_LENGTH = 4;

    private Esp8266ImageParser() {
    }

    public static Esp8266Image parse(byte[] input, ParserLimits limits,
            CancellationToken cancellationToken) throws DiagnosticException {
        Objects.requireNonNull(input, "input");
        Objects.requireNonNull(limits, "limits");
        Objects.requireNonNull(cancellationToken, "cancellationToken");
        cancellationToken.throwIfCancellationRequested();
        if (input.length > limits.maxInputBytes()) {
            throw failure(DiagnosticCode.LIMIT_EXCEEDED,
                "ESP8266 image exceeds the configured input-byte limit", 0, input.length);
        }
        validatePrefix(input);
        BoundedLittleEndianReader reader = new BoundedLittleEndianReader(input,
            new SourceRange(0, input.length), limits, cancellationToken);
        int magic = reader.readUnsignedByte();
        if (magic == Esp8266ImageVersion.VERSION_1.magic()) {
            return parseVersion1(input, reader, limits, cancellationToken);
        }
        return parseVersion2(input, reader, limits, cancellationToken);
    }

    private static Esp8266Image parseVersion1(byte[] input,
            BoundedLittleEndianReader reader, ParserLimits limits,
            CancellationToken cancellationToken) throws DiagnosticException {
        CommonHeader common = readCommonHeaderAfterMagic(reader, false);
        validateObjectCount(common.segmentCount(), limits);
        List<Esp8266ImageSegment> segments = new ArrayList<>(common.segmentCount());
        Checksum checksum = new Checksum();
        readSegments(reader, common.segmentCount(), segments, checksum, cancellationToken);
        int storedChecksum = readChecksumAndPadding(reader, checksum.value());
        requireNoTrailingData(reader);
        validateEntryPoint(common.entryPoint(), segments);
        Esp8266ImageHeader header = new Esp8266ImageHeader(
            Esp8266ImageVersion.VERSION_1, common.segmentCount(), common.flashMode(),
            common.flashSizeFrequency(), common.entryPoint(),
            new SourceRange(0, Esp8266ImageDetector.HEADER_LENGTH));
        return new Esp8266Image(header, segments, storedChecksum, checksum.value(),
            OptionalLong.empty(), OptionalLong.empty(), new SourceRange(0, input.length));
    }

    private static Esp8266Image parseVersion2(byte[] input,
            BoundedLittleEndianReader reader, ParserLimits limits,
            CancellationToken cancellationToken) throws DiagnosticException {
        CommonHeader outer = readCommonHeaderAfterMagic(reader, true);
        long firstHeaderOffset = reader.sourcePosition();
        SegmentFields firstFields = readSegmentFields(reader);
        if (firstFields.loadAddress() != 0) {
            throw failure(DiagnosticCode.ESP8266_HEADER_INVALID,
                "ESP8266 version 2 IROM segment must use encoded address zero",
                firstHeaderOffset, 4);
        }
        Esp8266ImageSegment first = readSegmentData(reader, 0, firstFields, true,
            firstHeaderOffset);
        long innerHeaderOffset = reader.sourcePosition();
        if (reader.remaining() < Esp8266ImageDetector.HEADER_LENGTH) {
            throw failure(DiagnosticCode.ESP8266_HEADER_TRUNCATED,
                "ESP8266 version 2 nested header is truncated", innerHeaderOffset,
                reader.remaining());
        }
        int innerMagic = reader.readUnsignedByte();
        if (innerMagic != Esp8266ImageVersion.VERSION_1.magic()) {
            throw failure(DiagnosticCode.ESP8266_HEADER_INVALID,
                "ESP8266 version 2 nested header magic is invalid", innerHeaderOffset, 1);
        }
        CommonHeader inner = readCommonHeaderAfterMagic(reader, false);
        if (outer.flashMode() != inner.flashMode()
            || outer.flashSizeFrequency() != inner.flashSizeFrequency()
            || outer.entryPoint() != inner.entryPoint()) {
            throw failure(DiagnosticCode.ESP8266_HEADER_INVALID,
                "ESP8266 version 2 outer and nested headers disagree",
                innerHeaderOffset, Esp8266ImageDetector.HEADER_LENGTH);
        }
        int totalSegments = Math.addExact(inner.segmentCount(), 1);
        validateObjectCount(totalSegments, limits);
        List<Esp8266ImageSegment> segments = new ArrayList<>(totalSegments);
        segments.add(first);
        Checksum checksum = new Checksum();
        readSegments(reader, inner.segmentCount(), segments, checksum, cancellationToken);
        int storedChecksum = readChecksumAndPadding(reader, checksum.value());
        if (reader.remaining() < SDK_CRC_LENGTH) {
            throw failure(DiagnosticCode.ESP8266_CRC_MISMATCH,
                "ESP8266 version 2 SDK CRC is truncated", reader.sourcePosition(),
                reader.remaining());
        }
        if (reader.remaining() > SDK_CRC_LENGTH) {
            throw failure(DiagnosticCode.ESP8266_TRAILING_DATA,
                "ESP8266 version 2 image has unexpected trailing data",
                reader.sourcePosition() + SDK_CRC_LENGTH,
                reader.remaining() - SDK_CRC_LENGTH);
        }
        long storedCrc = reader.readUnsignedInt();
        long calculatedCrc = calculateSdkCrc32(input, input.length - SDK_CRC_LENGTH);
        if (storedCrc != calculatedCrc) {
            throw failure(DiagnosticCode.ESP8266_CRC_MISMATCH,
                "ESP8266 version 2 SDK CRC does not match", input.length - 4L, 4);
        }
        validateEntryPoint(inner.entryPoint(), segments);
        Esp8266ImageHeader header = new Esp8266ImageHeader(
            Esp8266ImageVersion.VERSION_2, totalSegments, inner.flashMode(),
            inner.flashSizeFrequency(), inner.entryPoint(),
            new SourceRange(0, Esp8266ImageDetector.HEADER_LENGTH));
        return new Esp8266Image(header, segments, storedChecksum, checksum.value(),
            OptionalLong.of(storedCrc), OptionalLong.of(calculatedCrc),
            new SourceRange(0, input.length));
    }

    private static void readSegments(BoundedLittleEndianReader reader, int count,
            List<Esp8266ImageSegment> segments, Checksum checksum,
            CancellationToken cancellationToken) throws DiagnosticException {
        for (int index = 0; index < count; index++) {
            cancellationToken.throwIfCancellationRequested();
            long headerOffset = reader.sourcePosition();
            SegmentFields fields = readSegmentFields(reader);
            Esp8266ImageSegment segment = readSegmentData(reader, segments.size(), fields,
                false, headerOffset);
            for (Esp8266ImageSegment previous : segments) {
                if (!previous.flashMapped()
                    && segment.directTargetRange().overlaps(previous.directTargetRange())) {
                    throw failure(DiagnosticCode.ESP8266_SEGMENT_OVERLAP,
                        "ESP8266 RAM segments overlap", headerOffset, 4);
                }
            }
            for (byte value : segment.data()) {
                checksum.include(value);
            }
            segments.add(segment);
        }
    }

    private static SegmentFields readSegmentFields(BoundedLittleEndianReader reader)
            throws DiagnosticException {
        long headerOffset = reader.sourcePosition();
        if (reader.remaining() < SEGMENT_HEADER_LENGTH) {
            throw failure(DiagnosticCode.ESP8266_SEGMENT_HEADER_TRUNCATED,
                "ESP8266 segment header is truncated", headerOffset, reader.remaining());
        }
        long loadAddress = reader.readUnsignedInt();
        long lengthOffset = reader.sourcePosition();
        long length = reader.readUnsignedInt();
        if (length == 0 || length >= MAX_SEGMENT_LENGTH || (length & 3) != 0
            || loadAddress + length > 0x1_0000_0000L) {
            throw failure(DiagnosticCode.ESP8266_SEGMENT_LENGTH_INVALID,
                "ESP8266 segment length is invalid", lengthOffset, 4);
        }
        return new SegmentFields(loadAddress, length);
    }

    private static Esp8266ImageSegment readSegmentData(BoundedLittleEndianReader reader,
            int index, SegmentFields fields, boolean flashMapped, long headerOffset)
            throws DiagnosticException {
        long dataOffset = reader.sourcePosition();
        if (fields.length() > reader.remaining()) {
            throw failure(DiagnosticCode.ESP8266_SEGMENT_TRUNCATED,
                "ESP8266 segment data is truncated", dataOffset, reader.remaining());
        }
        byte[] data = reader.readBytes((int) fields.length());
        return new Esp8266ImageSegment(index, fields.loadAddress(), data, flashMapped,
            new SourceRange(headerOffset, SEGMENT_HEADER_LENGTH),
            new SourceRange(dataOffset, fields.length()));
    }

    private static int readChecksumAndPadding(BoundedLittleEndianReader reader,
            int calculatedChecksum) throws DiagnosticException {
        long paddingOffset = reader.sourcePosition();
        int paddingLength = (int) (15 - (paddingOffset % 16));
        if (reader.remaining() < paddingLength + 1L) {
            throw failure(DiagnosticCode.ESP8266_SEGMENT_TRUNCATED,
                "ESP8266 checksum footer is truncated", paddingOffset, reader.remaining());
        }
        reader.skip(paddingLength);
        long checksumOffset = reader.sourcePosition();
        int storedChecksum = reader.readUnsignedByte();
        if (storedChecksum != calculatedChecksum) {
            throw failure(DiagnosticCode.ESP8266_CHECKSUM_MISMATCH,
                "ESP8266 checksum does not match RAM segment data", checksumOffset, 1);
        }
        return storedChecksum;
    }

    private static CommonHeader readCommonHeaderAfterMagic(
            BoundedLittleEndianReader reader, boolean version2) throws DiagnosticException {
        int segmentCount = reader.readUnsignedByte();
        int flashMode = reader.readUnsignedByte();
        int flashSizeFrequency = reader.readUnsignedByte();
        long entryPoint = reader.readUnsignedInt();
        if (version2 && segmentCount != Esp8266ImageDetector.VERSION_2_MARKER) {
            throw failure(DiagnosticCode.ESP8266_HEADER_INVALID,
                "ESP8266 version 2 marker is invalid", 1, 1);
        }
        if (!version2 && (segmentCount == 0
            || segmentCount > Esp8266ImageDetector.MAX_SEGMENTS)) {
            throw failure(DiagnosticCode.ESP8266_HEADER_INVALID,
                "ESP8266 version 1 segment count is invalid",
                reader.sourcePosition() - 7, 1);
        }
        if ((entryPoint & 1) != 0) {
            throw failure(DiagnosticCode.ESP8266_ENTRY_INVALID,
                "ESP8266 entry point is not instruction aligned",
                reader.sourcePosition() - 4, 4);
        }
        return new CommonHeader(segmentCount, flashMode, flashSizeFrequency, entryPoint);
    }

    private static void validateEntryPoint(long entryPoint,
            List<Esp8266ImageSegment> segments) throws DiagnosticException {
        boolean withinRam = segments.stream().filter(segment -> !segment.flashMapped())
            .anyMatch(segment -> entryPoint >= segment.directTargetRange().start()
                && entryPoint < segment.directTargetRange().endExclusive());
        if (!withinRam) {
            throw failure(DiagnosticCode.ESP8266_ENTRY_INVALID,
                "ESP8266 entry point is outside directly mapped RAM segments", 4, 4);
        }
    }

    private static void validateObjectCount(int count, ParserLimits limits)
            throws DiagnosticException {
        if (count > limits.maxObjects()) {
            throw failure(DiagnosticCode.LIMIT_EXCEEDED,
                "ESP8266 segment count exceeds the configured object limit", 1, 1);
        }
    }

    private static void requireNoTrailingData(BoundedLittleEndianReader reader)
            throws DiagnosticException {
        if (reader.remaining() != 0) {
            throw failure(DiagnosticCode.ESP8266_TRAILING_DATA,
                "ESP8266 image has unexpected trailing data", reader.sourcePosition(),
                reader.remaining());
        }
    }

    private static void validatePrefix(byte[] input) throws DiagnosticException {
        if (input.length == 0) {
            throw failure(DiagnosticCode.ESP8266_MAGIC_INVALID,
                "Input does not start with an ESP8266 image magic", 0, 0);
        }
        int magic = Byte.toUnsignedInt(input[0]);
        if (magic != Esp8266ImageVersion.VERSION_1.magic()
            && magic != Esp8266ImageVersion.VERSION_2.magic()) {
            throw failure(DiagnosticCode.ESP8266_MAGIC_INVALID,
                "Input does not start with an ESP8266 image magic", 0, 1);
        }
        if (input.length < Esp8266ImageDetector.HEADER_LENGTH) {
            throw failure(DiagnosticCode.ESP8266_HEADER_TRUNCATED,
                "ESP8266 image header is truncated", 0, input.length);
        }
    }

    private static long calculateSdkCrc32(byte[] input, int length) {
        CRC32 crc32 = new CRC32();
        crc32.update(input, 0, length);
        long crc = crc32.getValue();
        return (crc & 0x8000_0000L) != 0 ? crc ^ 0xffff_ffffL : crc + 1;
    }

    private static DiagnosticException failure(DiagnosticCode code, String message,
            long offset, long length) {
        return new DiagnosticException(Diagnostic.error(code, message,
            new SourceRange(offset, length)));
    }

    private record CommonHeader(
            int segmentCount,
            int flashMode,
            int flashSizeFrequency,
            long entryPoint) {
    }

    private record SegmentFields(long loadAddress, long length) {
    }

    private static final class Checksum {
        private int value = CHECKSUM_SEED;

        int value() {
            return value;
        }

        void include(byte next) {
            value ^= Byte.toUnsignedInt(next);
        }
    }
}
