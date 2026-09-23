package io.github.rezabakhshi.embedra.formats.esp;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.core.io.SourceRange;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/** Bounded validation and discovery of MD5-protected ESP partition tables. */
public final class EspPartitionTableDiscovery {
    public static final long DEFAULT_OFFSET = 0x8000;

    public static final int TABLE_SIZE = 0x1000;

    private static final int ENTRY_SIZE = 32;

    private static final int ENTRY_AREA_SIZE = 0xc00;

    private static final int ENTRY_MAGIC = 0x50aa;

    private static final int MD5_MAGIC = 0xebeb;

    private EspPartitionTableDiscovery() {
    }

    public static EspPartitionTable discover(byte[] flash, ParserLimits limits,
            CancellationToken cancellation) throws DiagnosticException {
        validateInput(flash, limits, cancellation);
        DiagnosticException strongestFailure = null;
        if (hasCandidateMagic(flash, DEFAULT_OFFSET)) {
            try {
                return parseCandidate(flash, DEFAULT_OFFSET,
                    EspPartitionDiscoveryMethod.DEFAULT_OFFSET, limits, cancellation);
            }
            catch (DiagnosticException failure) {
                rethrowResourceFailure(failure);
                strongestFailure = stronger(strongestFailure, failure);
            }
        }
        for (long offset = 0; offset + ENTRY_SIZE <= flash.length;
                offset += TABLE_SIZE) {
            cancellation.throwIfCancellationRequested();
            if (offset == DEFAULT_OFFSET || !hasCandidateMagic(flash, offset)) {
                continue;
            }
            try {
                return parseCandidate(flash, offset,
                    EspPartitionDiscoveryMethod.BOUNDED_SCAN, limits, cancellation);
            }
            catch (DiagnosticException failure) {
                rethrowResourceFailure(failure);
                strongestFailure = stronger(strongestFailure, failure);
            }
        }
        if (strongestFailure != null
            && strongestFailure.diagnostic().code()
                == DiagnosticCode.ESP_PARTITION_MD5_MISMATCH) {
            throw strongestFailure;
        }
        throw failure(DiagnosticCode.ESP_PARTITION_NOT_FOUND,
            "No structurally valid MD5-protected ESP partition table was found",
            0, flash.length);
    }

    public static EspPartitionTable parseAt(byte[] flash, long offset,
            ParserLimits limits, CancellationToken cancellation)
            throws DiagnosticException {
        validateInput(flash, limits, cancellation);
        if (offset < 0 || (offset % TABLE_SIZE) != 0 || offset > Integer.MAX_VALUE) {
            throw failure(DiagnosticCode.ESP_PARTITION_OFFSET_INVALID,
                "Explicit partition-table offset must be a sector-aligned input offset",
                0, 0);
        }
        return parseCandidate(flash, offset, EspPartitionDiscoveryMethod.EXPLICIT_OFFSET,
            limits, cancellation);
    }

    private static EspPartitionTable parseCandidate(byte[] flash, long offset,
            EspPartitionDiscoveryMethod method, ParserLimits limits,
            CancellationToken cancellation) throws DiagnosticException {
        if (offset > flash.length || flash.length - offset < TABLE_SIZE) {
            long available = offset > flash.length ? 0 : flash.length - offset;
            throw failure(DiagnosticCode.ESP_PARTITION_TRUNCATED,
                "ESP partition-table sector is truncated", Math.min(offset, flash.length),
                available);
        }
        int tableOffset = (int) offset;
        List<EspPartitionEntry> entries = new ArrayList<>();
        EspFlashRange tableRange = new EspFlashRange(offset, TABLE_SIZE);
        for (int relative = 0; relative < ENTRY_AREA_SIZE; relative += ENTRY_SIZE) {
            cancellation.throwIfCancellationRequested();
            int entryOffset = tableOffset + relative;
            int magic = unsignedShort(flash, entryOffset);
            if (magic == MD5_MAGIC) {
                return finishTable(flash, tableOffset, relative, method, tableRange,
                    entries);
            }
            if (magic != ENTRY_MAGIC) {
                throw failure(DiagnosticCode.ESP_PARTITION_INVALID,
                    entries.isEmpty() ? "Partition-table entry magic is invalid"
                        : "Partition table ended without an MD5 record",
                    entryOffset, ENTRY_SIZE);
            }
            if (entries.size() >= limits.maxObjects()) {
                throw failure(DiagnosticCode.LIMIT_EXCEEDED,
                    "ESP partition count exceeds the configured object limit",
                    entryOffset, ENTRY_SIZE);
            }
            EspPartitionEntry entry = readEntry(flash, entryOffset, entries.size());
            validateEntry(entry, flash.length, tableRange, entries);
            entries.add(entry);
        }
        throw failure(DiagnosticCode.ESP_PARTITION_INVALID,
            "ESP partition table has no MD5 record", tableOffset, ENTRY_AREA_SIZE);
    }

    private static EspPartitionTable finishTable(byte[] flash, int tableOffset,
            int md5RelativeOffset, EspPartitionDiscoveryMethod method,
            EspFlashRange tableRange, List<EspPartitionEntry> entries)
            throws DiagnosticException {
        int markerOffset = tableOffset + md5RelativeOffset;
        if (entries.isEmpty() || !allValue(flash, markerOffset + 2, 14, 0xff)) {
            throw failure(DiagnosticCode.ESP_PARTITION_INVALID,
                "ESP partition-table MD5 record is malformed", markerOffset,
                ENTRY_SIZE);
        }
        byte[] stored = Arrays.copyOfRange(flash, markerOffset + 16,
            markerOffset + ENTRY_SIZE);
        byte[] calculated = md5(flash, tableOffset, md5RelativeOffset);
        SourceRange digestRange = new SourceRange(markerOffset + 16L, 16);
        if (!MessageDigest.isEqual(stored, calculated)) {
            throw new DiagnosticException(Diagnostic.error(
                DiagnosticCode.ESP_PARTITION_MD5_MISMATCH,
                "ESP partition-table MD5 does not match its entries", digestRange));
        }
        return new EspPartitionTable(method, tableRange,
            new SourceRange(tableOffset, TABLE_SIZE), entries, stored, calculated,
            digestRange);
    }

    private static EspPartitionEntry readEntry(byte[] flash, int offset, int index)
            throws DiagnosticException {
        String label = boundedLabel(flash, offset + 12, offset);
        long partitionOffset = unsignedInt(flash, offset + 4);
        long partitionSize = unsignedInt(flash, offset + 8);
        try {
            return new EspPartitionEntry(index, label,
                Byte.toUnsignedInt(flash[offset + 2]),
                Byte.toUnsignedInt(flash[offset + 3]),
                new EspFlashRange(partitionOffset, partitionSize),
                unsignedInt(flash, offset + 28), new SourceRange(offset, ENTRY_SIZE));
        }
        catch (IllegalArgumentException | ArithmeticException failure) {
            throw failure(DiagnosticCode.ESP_PARTITION_INVALID,
                "ESP partition entry has an invalid range or field", offset,
                ENTRY_SIZE);
        }
    }

    private static void validateEntry(EspPartitionEntry entry, int flashLength,
            EspFlashRange tableRange, List<EspPartitionEntry> previous)
            throws DiagnosticException {
        if (entry.flashRange().endExclusive() > flashLength
            || entry.flashRange().overlaps(tableRange)
            || previous.stream().anyMatch(candidate ->
                candidate.flashRange().overlaps(entry.flashRange()))
            || previous.stream().anyMatch(candidate ->
                candidate.label().equals(entry.label()))) {
            throw failure(DiagnosticCode.ESP_PARTITION_INVALID,
                "ESP partition entry is outside flash, overlaps, or duplicates a label",
                entry.sourceRange().offset(), entry.sourceRange().length());
        }
    }

    private static String boundedLabel(byte[] flash, int offset, int entryOffset)
            throws DiagnosticException {
        int length = 0;
        while (length < 16 && flash[offset + length] != 0) {
            length++;
        }
        if (length == 0 || length == 16) {
            throw failure(DiagnosticCode.ESP_PARTITION_INVALID,
                "ESP partition label is empty or not terminated", entryOffset,
                ENTRY_SIZE);
        }
        try {
            String value = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(flash, offset, length)).toString();
            if (value.codePoints().anyMatch(Character::isISOControl)) {
                throw failure(DiagnosticCode.ESP_PARTITION_INVALID,
                    "ESP partition label contains control characters", entryOffset,
                    ENTRY_SIZE);
            }
            return value;
        }
        catch (CharacterCodingException failure) {
            throw failure(DiagnosticCode.ESP_PARTITION_INVALID,
                "ESP partition label is not valid UTF-8", entryOffset, ENTRY_SIZE);
        }
    }

    private static void validateInput(byte[] flash, ParserLimits limits,
            CancellationToken cancellation) throws DiagnosticException {
        Objects.requireNonNull(flash, "flash");
        Objects.requireNonNull(limits, "limits");
        Objects.requireNonNull(cancellation, "cancellation");
        cancellation.throwIfCancellationRequested();
        if (flash.length > limits.maxInputBytes()) {
            throw failure(DiagnosticCode.LIMIT_EXCEEDED,
                "Flash image exceeds the configured input-byte limit", 0,
                flash.length);
        }
        if (TABLE_SIZE > limits.maxAllocationBytes()) {
            throw failure(DiagnosticCode.LIMIT_EXCEEDED,
                "Partition-table sector exceeds the allocation limit", 0, 0);
        }
    }

    private static boolean hasCandidateMagic(byte[] flash, long offset) {
        return offset >= 0 && offset + 1 < flash.length
            && unsignedShort(flash, (int) offset) == ENTRY_MAGIC;
    }

    private static DiagnosticException stronger(DiagnosticException previous,
            DiagnosticException candidate) {
        if (previous == null
            || candidate.diagnostic().code() == DiagnosticCode.ESP_PARTITION_MD5_MISMATCH) {
            return candidate;
        }
        return previous;
    }

    private static void rethrowResourceFailure(DiagnosticException failure)
            throws DiagnosticException {
        if (failure.diagnostic().code() == DiagnosticCode.LIMIT_EXCEEDED
            || failure.diagnostic().code() == DiagnosticCode.CANCELLED) {
            throw failure;
        }
    }

    private static boolean allValue(byte[] input, int offset, int length, int value) {
        for (int index = 0; index < length; index++) {
            if (Byte.toUnsignedInt(input[offset + index]) != value) {
                return false;
            }
        }
        return true;
    }

    private static int unsignedShort(byte[] input, int offset) {
        return Byte.toUnsignedInt(input[offset])
            | Byte.toUnsignedInt(input[offset + 1]) << 8;
    }

    private static long unsignedInt(byte[] input, int offset) {
        return Integer.toUnsignedLong(Byte.toUnsignedInt(input[offset])
            | Byte.toUnsignedInt(input[offset + 1]) << 8
            | Byte.toUnsignedInt(input[offset + 2]) << 16
            | Byte.toUnsignedInt(input[offset + 3]) << 24);
    }

    private static byte[] md5(byte[] input, int offset, int length) {
        try {
            MessageDigest digest = MessageDigest.getInstance("MD5");
            digest.update(input, offset, length);
            return digest.digest();
        }
        catch (NoSuchAlgorithmException failure) {
            throw new IllegalStateException("Required MD5 implementation unavailable",
                failure);
        }
    }

    private static DiagnosticException failure(DiagnosticCode code, String message,
            long offset, long length) {
        return new DiagnosticException(Diagnostic.error(code, message,
            new SourceRange(offset, length)));
    }
}
