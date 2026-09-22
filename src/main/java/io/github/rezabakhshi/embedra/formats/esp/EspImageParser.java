package io.github.rezabakhshi.embedra.formats.esp;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.core.io.BoundedLittleEndianReader;
import io.github.rezabakhshi.embedra.core.io.SourceRange;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/** Bounded pure parser and structural validator for ESP application images. */
public final class EspImageParser {
    private static final int SEGMENT_HEADER_LENGTH = 8;

    private static final long MAX_SEGMENT_LENGTH = 0x0100_0000L;

    private static final int CHECKSUM_SEED = 0xef;

    private static final int DIGEST_LENGTH = 32;

    private EspImageParser() {
    }

    public static EspImage parse(byte[] input, ParserLimits limits,
            CancellationToken cancellationToken) throws DiagnosticException {
        return parseInternal(input, null, limits, cancellationToken);
    }

    public static EspImage parseForChip(byte[] input, int expectedChipId,
            ParserLimits limits, CancellationToken cancellationToken) throws DiagnosticException {
        if (expectedChipId < 0 || expectedChipId > 0xffff) {
            throw new IllegalArgumentException("Expected chip ID must be an unsigned short");
        }
        return parseInternal(input, expectedChipId, limits, cancellationToken);
    }

    private static EspImage parseInternal(byte[] input, Integer expectedChipId,
            ParserLimits limits, CancellationToken cancellationToken) throws DiagnosticException {
        Objects.requireNonNull(input, "input");
        Objects.requireNonNull(limits, "limits");
        Objects.requireNonNull(cancellationToken, "cancellationToken");
        cancellationToken.throwIfCancellationRequested();
        if (input.length > limits.maxInputBytes()) {
            throw failure(DiagnosticCode.LIMIT_EXCEEDED,
                "ESP image exceeds the configured input-byte limit", 0, input.length);
        }
        validatePrefix(input);

        BoundedLittleEndianReader reader = new BoundedLittleEndianReader(input,
            new SourceRange(0, input.length), limits, cancellationToken);
        EspImageHeader header = readHeader(reader);
        if (expectedChipId != null && header.chipId() != expectedChipId) {
            throw failure(DiagnosticCode.ESP_CHIP_MISMATCH,
                "ESP image chip ID does not match the selected target", 12, 2);
        }
        if ((header.entryPoint() & 1) != 0) {
            throw failure(DiagnosticCode.ESP_ENTRY_INVALID,
                "ESP image entry point is not minimally instruction-aligned", 4, 4);
        }
        if (header.segmentCount() > limits.maxObjects()) {
            throw failure(DiagnosticCode.LIMIT_EXCEEDED,
                "ESP segment count exceeds the configured object limit", 1, 1);
        }

        int checksum = CHECKSUM_SEED;
        List<EspImageSegment> segments = new ArrayList<>(header.segmentCount());
        for (int index = 0; index < header.segmentCount(); index++) {
            cancellationToken.throwIfCancellationRequested();
            long segmentHeaderOffset = reader.sourcePosition();
            if (reader.remaining() < SEGMENT_HEADER_LENGTH) {
                throw failure(DiagnosticCode.ESP_SEGMENT_HEADER_TRUNCATED,
                    "ESP segment header is truncated", segmentHeaderOffset, reader.remaining());
            }
            long loadAddress = reader.readUnsignedInt();
            long lengthOffset = reader.sourcePosition();
            long length = reader.readUnsignedInt();
            if (length >= MAX_SEGMENT_LENGTH || (length & 3) != 0
                || loadAddress + length > 0x1_0000_0000L) {
                throw failure(DiagnosticCode.ESP_SEGMENT_LENGTH_INVALID,
                    "ESP segment length is invalid", lengthOffset, 4);
            }
            long dataOffset = reader.sourcePosition();
            if (length > reader.remaining()) {
                throw failure(DiagnosticCode.ESP_SEGMENT_TRUNCATED,
                    "ESP segment data is truncated", dataOffset, reader.remaining());
            }
            EspImageSegment candidate = new EspImageSegment(index, loadAddress,
                reader.readBytes((int) length),
                new SourceRange(segmentHeaderOffset, SEGMENT_HEADER_LENGTH),
                new SourceRange(dataOffset, length));
            for (EspImageSegment previous : segments) {
                if (candidate.targetRange().overlaps(previous.targetRange())) {
                    throw failure(DiagnosticCode.ESP_SEGMENT_OVERLAP,
                        "ESP segments have overlapping encoded target ranges",
                        segmentHeaderOffset, 4);
                }
            }
            for (byte value : candidate.data()) {
                checksum ^= Byte.toUnsignedInt(value);
            }
            segments.add(candidate);
        }

        long paddingOffset = reader.sourcePosition();
        int paddingLength = (int) (15 - (paddingOffset % 16));
        if (reader.remaining() < paddingLength + 1L) {
            throw failure(DiagnosticCode.ESP_SEGMENT_TRUNCATED,
                "ESP image checksum footer is truncated", paddingOffset, reader.remaining());
        }
        byte[] padding = reader.readBytes(paddingLength);
        long checksumOffset = reader.sourcePosition();
        int storedChecksum = reader.readUnsignedByte();
        if (storedChecksum != checksum) {
            throw failure(DiagnosticCode.ESP_CHECKSUM_MISMATCH,
                "ESP image checksum does not match segment data", checksumOffset, 1);
        }

        byte[] storedDigest = new byte[0];
        byte[] calculatedDigest = new byte[0];
        SourceRange digestRange = null;
        if (header.digestAppended()) {
            long digestOffset = reader.sourcePosition();
            if (reader.remaining() < DIGEST_LENGTH) {
                throw failure(DiagnosticCode.ESP_DIGEST_TRUNCATED,
                    "ESP image appended digest is truncated", digestOffset, reader.remaining());
            }
            storedDigest = reader.readBytes(DIGEST_LENGTH);
            calculatedDigest = sha256(input, (int) digestOffset);
            digestRange = new SourceRange(digestOffset, DIGEST_LENGTH);
            if (!MessageDigest.isEqual(storedDigest, calculatedDigest)) {
                throw failure(DiagnosticCode.ESP_DIGEST_MISMATCH,
                    "ESP image SHA-256 digest does not match", digestOffset, DIGEST_LENGTH);
            }
        }
        if (reader.remaining() != 0) {
            throw failure(DiagnosticCode.ESP_TRAILING_DATA,
                "ESP image has unexpected trailing data", reader.sourcePosition(),
                reader.remaining());
        }
        if (segments.stream().noneMatch(segment ->
                header.entryPoint() >= segment.targetRange().start()
                    && header.entryPoint() < segment.targetRange().endExclusive())) {
            throw failure(DiagnosticCode.ESP_ENTRY_INVALID,
                "ESP image entry point is outside all encoded segments", 4, 4);
        }

        EspImageFooter footer = new EspImageFooter(padding,
            new SourceRange(paddingOffset, paddingLength), storedChecksum, checksum,
            new SourceRange(checksumOffset, 1), storedDigest, calculatedDigest, digestRange);
        return new EspImage(header, segments, footer, new SourceRange(0, input.length));
    }

    private static void validatePrefix(byte[] input) throws DiagnosticException {
        if (input.length == 0 || Byte.toUnsignedInt(input[0]) != EspImageDetector.MAGIC) {
            throw failure(DiagnosticCode.ESP_MAGIC_INVALID,
                "Input does not start with the ESP image magic", 0, Math.min(1, input.length));
        }
        if (input.length < EspImageDetector.HEADER_LENGTH) {
            throw failure(DiagnosticCode.ESP_HEADER_TRUNCATED,
                "ESP image header is truncated", 0, input.length);
        }
    }

    private static EspImageHeader readHeader(BoundedLittleEndianReader reader)
            throws DiagnosticException {
        int magic = reader.readUnsignedByte();
        int segmentCount = reader.readUnsignedByte();
        int flashMode = reader.readUnsignedByte();
        int flashSizeFrequency = reader.readUnsignedByte();
        long entryPoint = reader.readUnsignedInt();
        int writeProtectPin = reader.readUnsignedByte();
        int clockAndQDrive = reader.readUnsignedByte();
        int dAndCsDrive = reader.readUnsignedByte();
        int hdAndWpDrive = reader.readUnsignedByte();
        int chipId = reader.readUnsignedShort();
        int minimumRevision = reader.readUnsignedByte();
        int minimumRevisionFull = reader.readUnsignedShort();
        int maximumRevisionFull = reader.readUnsignedShort();
        byte[] reserved = reader.readBytes(4);
        int digestFlag = reader.readUnsignedByte();
        if (segmentCount == 0 || segmentCount > EspImageDetector.MAX_SEGMENTS
            || digestFlag > 1 || !Arrays.equals(reserved, new byte[4])) {
            throw failure(DiagnosticCode.ESP_HEADER_INVALID,
                "ESP image extended header contains invalid structural values", 1, 23);
        }
        return new EspImageHeader(magic, segmentCount, flashMode, flashSizeFrequency,
            entryPoint, writeProtectPin, clockAndQDrive >>> 4, clockAndQDrive & 0xf,
            dAndCsDrive >>> 4, dAndCsDrive & 0xf, hdAndWpDrive >>> 4,
            hdAndWpDrive & 0xf, chipId, minimumRevision, minimumRevisionFull,
            maximumRevisionFull, digestFlag == 1,
            new SourceRange(0, EspImageDetector.HEADER_LENGTH));
    }

    private static byte[] sha256(byte[] input, int length) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(input, 0, length);
            return digest.digest();
        }
        catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("Required SHA-256 implementation unavailable",
                exception);
        }
    }

    private static DiagnosticException failure(DiagnosticCode code, String message,
            long offset, long length) {
        return new DiagnosticException(Diagnostic.error(code, message,
            new SourceRange(offset, length)));
    }
}
