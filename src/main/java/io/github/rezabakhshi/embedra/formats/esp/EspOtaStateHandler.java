package io.github.rezabakhshi.embedra.formats.esp;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticSeverity;
import io.github.rezabakhshi.embedra.core.io.SourceRange;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalInt;

/** ESP-IDF v6-compatible parser for the two redundant OTA select records. */
public final class EspOtaStateHandler implements EspPartitionHandler {
    private static final int RECORD_SIZE = 32;

    private static final int SECTOR_SIZE = 4096;

    private static final long ERASED_WORD = 0xffff_ffffL;

    @Override
    public EspPartitionHandlerKind kind() {
        return EspPartitionHandlerKind.OTA_STATE;
    }

    @Override
    public boolean supports(EspPartitionEntry entry) {
        return !entry.encrypted() && entry.type() == 1 && entry.subtype() == 0;
    }

    @Override
    public EspPartitionInspection inspect(EspExtractedPartition partition,
            ParserLimits limits, CancellationToken cancellation)
            throws DiagnosticException {
        cancellation.throwIfCancellationRequested();
        byte[] payload = partition.payload();
        SourceRange range = partition.sourceRange();
        if (payload.length < 2 * SECTOR_SIZE) {
            return invalid(partition, "OTA data partition is smaller than two sectors");
        }
        List<EspOtaSelectRecord> records = records(partition, cancellation);
        boolean erased = records.stream()
            .allMatch(record -> record.validity() == EspOtaRecordValidity.ERASED);
        boolean valid = records.stream()
            .anyMatch(record -> record.validity() == EspOtaRecordValidity.VALID);
        List<Diagnostic> diagnostics = valid || erased ? List.of()
            : List.of(warning("Neither OTA selection copy is valid", range));
        return new EspPartitionInspection(partition.entry(), kind(),
            erased ? EspPartitionDisposition.ERASED
                : valid ? EspPartitionDisposition.VALIDATED_METADATA
                    : EspPartitionDisposition.INVALID,
            range, Map.of("copyCount", "2"), diagnostics, false);
    }

    public EspOtaSelection select(EspExtractedPartition partition,
            EspPartitionTable table, List<String> populatedApplicationLabels,
            CancellationToken cancellation) throws DiagnosticException {
        List<EspOtaSelectRecord> records = records(partition, cancellation);
        List<EspPartitionEntry> otaPartitions = table.entries().stream()
            .filter(entry -> entry.type() == 0 && entry.subtype() >= 0x10
                && entry.subtype() <= 0x1f)
            .sorted(java.util.Comparator.comparingInt(EspPartitionEntry::subtype))
            .toList();
        Optional<EspOtaSelectRecord> selected = records.stream()
            .filter(record -> record.validity() == EspOtaRecordValidity.VALID)
            .max(java.util.Comparator.comparingLong(EspOtaSelectRecord::sequence));
        if (selected.isEmpty() || otaPartitions.isEmpty()) {
            return new EspOtaSelection(records, OptionalInt.empty(), Optional.empty());
        }
        int slot = (int) ((selected.orElseThrow().sequence() - 1)
            % otaPartitions.size());
        String label = otaPartitions.get(slot).label();
        if (!populatedApplicationLabels.contains(label)) {
            return new EspOtaSelection(records, OptionalInt.empty(), Optional.empty());
        }
        return new EspOtaSelection(records, OptionalInt.of(slot), Optional.of(label));
    }

    private static List<EspOtaSelectRecord> records(EspExtractedPartition partition,
            CancellationToken cancellation) throws DiagnosticException {
        byte[] payload = partition.payload();
        if (payload.length < 2 * SECTOR_SIZE) {
            return List.of(erasedRecord(partition, 0), erasedRecord(partition, 1));
        }
        List<EspOtaSelectRecord> records = new ArrayList<>(2);
        for (int copy = 0; copy < 2; copy++) {
            cancellation.throwIfCancellationRequested();
            int offset = copy * SECTOR_SIZE;
            SourceRange sourceRange = new SourceRange(
                partition.sourceRange().offset() + offset, RECORD_SIZE);
            if (allValue(payload, offset, RECORD_SIZE, 0xff)) {
                records.add(new EspOtaSelectRecord(copy, ERASED_WORD, ERASED_WORD,
                    EspOtaImageState.UNDEFINED, ERASED_WORD, ERASED_WORD,
                    EspOtaRecordValidity.ERASED, sourceRange));
                continue;
            }
            long sequence = unsignedInt(payload, offset);
            long rawState = unsignedInt(payload, offset + 24);
            long storedCrc = unsignedInt(payload, offset + 28);
            long calculatedCrc = otaSequenceCrc(sequence);
            EspOtaImageState state = state(rawState);
            EspOtaRecordValidity validity;
            if (sequence == ERASED_WORD || state == EspOtaImageState.INVALID
                || state == EspOtaImageState.ABORTED
                || state == EspOtaImageState.UNKNOWN) {
                validity = EspOtaRecordValidity.REJECTED_STATE;
            }
            else if (storedCrc != calculatedCrc) {
                validity = EspOtaRecordValidity.CRC_MISMATCH;
            }
            else {
                validity = EspOtaRecordValidity.VALID;
            }
            records.add(new EspOtaSelectRecord(copy, sequence, rawState, state,
                storedCrc, calculatedCrc, validity, sourceRange));
        }
        return List.copyOf(records);
    }

    public static long otaSequenceCrc(long sequence) {
        long crc = 0;
        for (int byteIndex = 0; byteIndex < 4; byteIndex++) {
            crc ^= (sequence >>> (byteIndex * 8)) & 0xff;
            for (int bit = 0; bit < 8; bit++) {
                crc = (crc & 1) != 0 ? (crc >>> 1) ^ 0xedb8_8320L : crc >>> 1;
            }
        }
        return (~crc) & 0xffff_ffffL;
    }

    private static EspOtaImageState state(long value) {
        return switch ((int) value) {
            case 0 -> EspOtaImageState.NEW;
            case 1 -> EspOtaImageState.PENDING_VERIFY;
            case 2 -> EspOtaImageState.VALID;
            case 3 -> EspOtaImageState.INVALID;
            case 4 -> EspOtaImageState.ABORTED;
            case -1 -> EspOtaImageState.UNDEFINED;
            default -> EspOtaImageState.UNKNOWN;
        };
    }

    private EspPartitionInspection invalid(EspExtractedPartition partition,
            String message) {
        return new EspPartitionInspection(partition.entry(), kind(),
            EspPartitionDisposition.INVALID, partition.sourceRange(), Map.of(),
            List.of(warning(message, partition.sourceRange())), false);
    }

    private static EspOtaSelectRecord erasedRecord(EspExtractedPartition partition,
            int copy) {
        long relative = (long) copy * SECTOR_SIZE;
        long available = Math.max(0, partition.sourceRange().length() - relative);
        return new EspOtaSelectRecord(copy, ERASED_WORD, ERASED_WORD,
            EspOtaImageState.UNDEFINED, ERASED_WORD, ERASED_WORD,
            EspOtaRecordValidity.ERASED,
            new SourceRange(partition.sourceRange().offset()
                + Math.min(relative, partition.sourceRange().length()),
                Math.min(RECORD_SIZE, available)));
    }

    private static Diagnostic warning(String message, SourceRange range) {
        return new Diagnostic(DiagnosticCode.ESP_PARTITION_HANDLER_INVALID,
            DiagnosticSeverity.WARNING, message, Optional.of(range));
    }

    private static boolean allValue(byte[] input, int offset, int length,
            int expected) {
        for (int index = 0; index < length; index++) {
            if (Byte.toUnsignedInt(input[offset + index]) != expected) {
                return false;
            }
        }
        return true;
    }

    private static long unsignedInt(byte[] input, int offset) {
        return Integer.toUnsignedLong(Byte.toUnsignedInt(input[offset])
            | Byte.toUnsignedInt(input[offset + 1]) << 8
            | Byte.toUnsignedInt(input[offset + 2]) << 16
            | Byte.toUnsignedInt(input[offset + 3]) << 24);
    }
}
