package io.github.rezabakhshi.embedra.targets.stm8.vector;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.targets.stm8.catalog.Stm8PartRecord;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Pure parser and scorer for STM8 interrupt vector tables anchored at 0x008000.
 */
public final class Stm8VectorTableParser {

    public static final int VECTOR_COUNT = 32;

    public static final int ENTRY_SIZE_BYTES = 4;

    public static final int TABLE_SIZE_BYTES = VECTOR_COUNT * ENTRY_SIZE_BYTES; // 128 bytes

    public static final long DEFAULT_TABLE_BASE = 0x008000L;

    public static final int JPF_OPCODE = 0x82;

    private Stm8VectorTableParser() {
    }

    public static Stm8VectorTable parse(
            byte[] bytes, Stm8PartRecord part, ParserLimits limits, CancellationToken token)
            throws DiagnosticException {
        return parse(bytes, 0, DEFAULT_TABLE_BASE, part, limits, token);
    }

    public static Stm8VectorTable parse(
            byte[] bytes, long tableBaseAddress, Stm8PartRecord part, ParserLimits limits, CancellationToken token)
            throws DiagnosticException {
        return parse(bytes, 0, tableBaseAddress, part, limits, token);
    }

    public static Stm8VectorTable parse(
            byte[] bytes,
            int offset,
            long tableBaseAddress,
            Stm8PartRecord part,
            ParserLimits limits,
            CancellationToken token)
            throws DiagnosticException {
        Objects.requireNonNull(bytes, "bytes must not be null");
        Objects.requireNonNull(limits, "limits must not be null");
        Objects.requireNonNull(token, "token must not be null");

        token.throwIfCancellationRequested();

        if (bytes.length > limits.maxInputBytes() || bytes.length > limits.maxAllocationBytes()) {
            throw new DiagnosticException(Diagnostic.error(
                DiagnosticCode.LIMIT_EXCEEDED,
                "Vector table input exceeds configured parser limits: " + bytes.length,
                null));
        }

        if (offset < 0 || offset + TABLE_SIZE_BYTES > bytes.length) {
            throw new DiagnosticException(Diagnostic.error(
                DiagnosticCode.STM8_VECTOR_TABLE_TRUNCATED,
                String.format("Truncated STM8 vector table: available %d bytes, required %d bytes from offset %d",
                    bytes.length - Math.max(0, offset), TABLE_SIZE_BYTES, offset),
                null));
        }

        // Count target address frequencies to detect stub handlers
        Map<Long, Integer> targetCounts = new HashMap<>();
        for (int i = 0; i < VECTOR_COUNT; i++) {
            int entryOffset = offset + (i * ENTRY_SIZE_BYTES);
            int opcode = bytes[entryOffset] & 0xFF;
            if (opcode == JPF_OPCODE) {
                long target = read24(bytes, entryOffset + 1);
                targetCounts.merge(target, 1, Integer::sum);
            }
        }

        int validOpcodeCount = 0;
        int validTargetCount = 0;
        Set<Long> uniqueTargets = new HashSet<>();
        boolean resetVectorValid = false;
        long resetTarget = 0L;

        List<Stm8VectorEntry> entries = new ArrayList<>(VECTOR_COUNT);

        long flashStart = part != null ? part.flashStart() : DEFAULT_TABLE_BASE;
        long flashEnd = part != null ? part.flashEnd() : 0x03FFFFL;

        for (int i = 0; i < VECTOR_COUNT; i++) {
            Stm8VectorSlot slot = Stm8VectorSlot.fromIndex(i);
            int entryOffset = offset + (i * ENTRY_SIZE_BYTES);
            int opcode = bytes[entryOffset] & 0xFF;
            long target = read24(bytes, entryOffset + 1);

            boolean validOpcode = (opcode == JPF_OPCODE);
            boolean validTarget = false;

            if (validOpcode) {
                validOpcodeCount++;
                uniqueTargets.add(target);

                // Target must be within physical flash bounds
                boolean inFlash = (target >= flashStart && target <= flashEnd);
                // Cannot point into the vector table itself (0x008000..0x00807F)
                boolean outsideTable = (target < tableBaseAddress || target >= tableBaseAddress + TABLE_SIZE_BYTES);

                if (inFlash && outsideTable) {
                    validTarget = true;
                    validTargetCount++;
                }

                if (i == 0) {
                    resetVectorValid = validTarget;
                    resetTarget = target;
                }
            }

            boolean isStub = targetCounts.getOrDefault(target, 0) > 1 && i != 0;
            String family = part != null ? part.family() : "STM8S";
            String handlerLabel = slot.handlerLabelForFamily(family);

            entries.add(new Stm8VectorEntry(
                slot,
                tableBaseAddress + (i * (long) ENTRY_SIZE_BYTES),
                opcode,
                target,
                validOpcode,
                validTarget,
                handlerLabel,
                slot.description(),
                isStub
            ));
        }

        Stm8VectorTableScore score = Stm8VectorTableScore.evaluate(
            validOpcodeCount,
            validTargetCount,
            uniqueTargets.size(),
            resetVectorValid
        );

        return new Stm8VectorTable(tableBaseAddress, entries, score, resetTarget);
    }

    public static Stm8VectorTable parseAndValidate(
            byte[] bytes,
            int offset,
            long tableBaseAddress,
            Stm8PartRecord part,
            ParserLimits limits,
            CancellationToken token)
            throws DiagnosticException {
        Stm8VectorTable table = parse(bytes, offset, tableBaseAddress, part, limits, token);
        if (!table.score().resetVectorValid() || table.score().validTargetCount() == 0) {
            throw new DiagnosticException(Diagnostic.error(
                DiagnosticCode.STM8_VECTOR_TABLE_INVALID,
                "STM8 vector table validation failed: " + table.score().reasoning(),
                null));
        }
        return table;
    }

    public static Stm8VectorTable discover(
            byte[] imageBytes,
            long imageBaseAddress,
            Stm8PartRecord part,
            ParserLimits limits,
            CancellationToken token)
            throws DiagnosticException {
        Objects.requireNonNull(imageBytes, "imageBytes must not be null");

        int offset;
        if (imageBaseAddress == DEFAULT_TABLE_BASE) {
            offset = 0;
        } else if (imageBaseAddress == 0L && imageBytes.length >= DEFAULT_TABLE_BASE + TABLE_SIZE_BYTES) {
            offset = (int) DEFAULT_TABLE_BASE;
        } else if (DEFAULT_TABLE_BASE >= imageBaseAddress
            && (DEFAULT_TABLE_BASE + TABLE_SIZE_BYTES) <= (imageBaseAddress + imageBytes.length)) {
            offset = (int) (DEFAULT_TABLE_BASE - imageBaseAddress);
        } else {
            throw new DiagnosticException(Diagnostic.error(
                DiagnosticCode.STM8_VECTOR_TABLE_TRUNCATED,
                "Image does not contain the STM8 vector table range 0x008000-0x00807F",
                null));
        }

        return parse(imageBytes, offset, DEFAULT_TABLE_BASE, part, limits, token);
    }

    private static long read24(byte[] bytes, int offset) {
        return ((bytes[offset] & 0xFFL) << 16)
            | ((bytes[offset + 1] & 0xFFL) << 8)
            | (bytes[offset + 2] & 0xFFL);
    }
}
