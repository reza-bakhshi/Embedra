package io.github.rezabakhshi.embedra.targets.atmel.vector;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.targets.atmel.catalog.AtmelPartRecord;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Pure parser and scorer for Atmel / Microchip interrupt vector tables across 8-bit AVR and 32-bit SAM devices.
 */
public final class AtmelVectorTableParser {

    public static final int AVR_JMP_OPCODE_BYTE0 = 0x0C;

    public static final int AVR_JMP_OPCODE_BYTE1 = 0x94;

    public static final int AVR_RJMP_OPCODE_MASK = 0xF000;

    public static final int AVR_RJMP_OPCODE_BASE = 0xC000;

    private AtmelVectorTableParser() {
    }

    public static AtmelVectorTable parse(
            byte[] bytes,
            AtmelPartRecord part,
            ParserLimits limits,
            CancellationToken token)
            throws DiagnosticException {
        return parse(bytes, 0, part.flashStart(), part, limits, token);
    }

    public static AtmelVectorTable parse(
            byte[] bytes,
            long tableBaseAddress,
            AtmelPartRecord part,
            ParserLimits limits,
            CancellationToken token)
            throws DiagnosticException {
        return parse(bytes, 0, tableBaseAddress, part, limits, token);
    }

    public static AtmelVectorTable parse(
            byte[] bytes,
            int offset,
            long tableBaseAddress,
            AtmelPartRecord part,
            ParserLimits limits,
            CancellationToken token)
            throws DiagnosticException {
        Objects.requireNonNull(bytes, "bytes must not be null");
        Objects.requireNonNull(part, "part must not be null");
        Objects.requireNonNull(limits, "limits must not be null");
        Objects.requireNonNull(token, "token must not be null");

        token.throwIfCancellationRequested();

        if (bytes.length > limits.maxInputBytes() || bytes.length > limits.maxAllocationBytes()) {
            throw new DiagnosticException(Diagnostic.error(
                DiagnosticCode.LIMIT_EXCEEDED,
                "Vector table input exceeds configured parser limits: " + bytes.length,
                null));
        }

        int count = part.vectorCount();
        int stride = part.vectorStrideBytes();
        int tableBytes = count * stride;

        if (offset < 0 || offset + tableBytes > bytes.length) {
            throw new DiagnosticException(Diagnostic.error(
                DiagnosticCode.ATMEL_VECTOR_TABLE_TRUNCATED,
                String.format(
                    "Truncated Atmel vector table for %s: available %d bytes, required %d bytes from offset %d",
                    part.exactPart(), bytes.length - Math.max(0, offset), tableBytes, offset),
                null));
        }

        List<AtmelVectorSlot> slots = AtmelVectorSlot.slotsFor(part);
        List<AtmelVectorEntry> entries = new ArrayList<>(count);

        if (part.isSam()) {
            parseSamVectors(bytes, offset, tableBaseAddress, part, slots, count, entries, token);
        } else if (stride == 2) {
            parseAvrRjmpVectors(bytes, offset, tableBaseAddress, part, slots, count, entries, token);
        } else {
            parseAvrJmpVectors(bytes, offset, tableBaseAddress, part, slots, count, entries, token);
        }

        // Count targets to determine stubs
        Map<Long, Integer> targetCounts = new HashMap<>();
        for (AtmelVectorEntry entry : entries) {
            if (entry.isValid()) {
                targetCounts.merge(entry.targetAddress(), 1, Integer::sum);
            }
        }

        // Reconstruct with isStub metadata
        List<AtmelVectorEntry> finalEntries = new ArrayList<>(entries.size());
        int validOpcodeCount = 0;
        int validTargetCount = 0;
        Set<Long> uniqueTargets = new HashSet<>();
        boolean resetValid = false;

        for (AtmelVectorEntry entry : entries) {
            boolean isStub = false;
            if (entry.isValid()) {
                validOpcodeCount++;
                validTargetCount++;
                uniqueTargets.add(entry.targetAddress());
                if (targetCounts.getOrDefault(entry.targetAddress(), 0) > 1 && !entry.isReset()) {
                    isStub = true;
                }
                if (entry.isReset()) {
                    resetValid = true;
                }
            }
            finalEntries.add(new AtmelVectorEntry(
                entry.slot(), entry.entryAddress(), entry.targetAddress(),
                entry.rawInstruction(), entry.instructionType(),
                entry.isValid(), isStub, entry.canonicalLabel()
            ));
        }

        AtmelVectorTableScore score = AtmelVectorTableScore.evaluate(
            count, validOpcodeCount, validTargetCount, uniqueTargets.size(), resetValid
        );

        return new AtmelVectorTable(tableBaseAddress, part, finalEntries, score);
    }

    private static void parseAvrRjmpVectors(
            byte[] bytes, int offset, long tableBaseAddress, AtmelPartRecord part,
            List<AtmelVectorSlot> slots, int count, List<AtmelVectorEntry> entries,
            CancellationToken token) throws DiagnosticException {
        for (int i = 0; i < count; i++) {
            token.throwIfCancellationRequested();
            int entryOffset = offset + (i * 2);
            long entryAddr = tableBaseAddress + (i * 2L);
            AtmelVectorSlot slot = i < slots.size()
                ? slots.get(i)
                : new AtmelVectorSlot(i, "__vector_" + i, "Vector " + i);

            int op = (bytes[entryOffset] & 0xFF) | ((bytes[entryOffset + 1] & 0xFF) << 8);
            if ((op & AVR_RJMP_OPCODE_MASK) == AVR_RJMP_OPCODE_BASE) {
                int rel = op & 0x0FFF;
                if ((rel & 0x0800) != 0) {
                    rel |= ~0x0FFF;
                }
                long pcWord = (entryAddr / 2L) + 1L;
                long targetWord = pcWord + rel;
                long targetByte = (targetWord * 2L) & 0xFFFFFFFFL;

                boolean inRange = targetByte >= part.flashStart() && targetByte <= part.flashEnd();
                String label = (i == 0) ? "Reset_Handler" : slot.name();
                entries.add(new AtmelVectorEntry(
                    slot, entryAddr, targetByte, op,
                    AtmelVectorInstructionType.RJMP, inRange, false, label
                ));
            } else {
                entries.add(new AtmelVectorEntry(
                    slot, entryAddr, 0L, op,
                    AtmelVectorInstructionType.INVALID, false, false, "Invalid_Vector_" + i
                ));
            }
        }
    }

    private static void parseAvrJmpVectors(
            byte[] bytes, int offset, long tableBaseAddress, AtmelPartRecord part,
            List<AtmelVectorSlot> slots, int count, List<AtmelVectorEntry> entries,
            CancellationToken token) throws DiagnosticException {
        for (int i = 0; i < count; i++) {
            token.throwIfCancellationRequested();
            int entryOffset = offset + (i * 4);
            long entryAddr = tableBaseAddress + (i * 4L);
            AtmelVectorSlot slot = i < slots.size()
                ? slots.get(i)
                : new AtmelVectorSlot(i, "__vector_" + i, "Vector " + i);

            int b0 = bytes[entryOffset] & 0xFF;
            int b1 = bytes[entryOffset + 1] & 0xFF;
            int b2 = bytes[entryOffset + 2] & 0xFF;
            int b3 = bytes[entryOffset + 3] & 0xFF;

            long raw = (b0) | ((long) b1 << 8) | ((long) b2 << 16) | ((long) b3 << 24);

            if (b0 == AVR_JMP_OPCODE_BYTE0 && (b1 & 0xFE) == AVR_JMP_OPCODE_BYTE1) {
                long targetWord = b2 | (b3 << 8);
                if ((b1 & 0x01) != 0) {
                    targetWord |= (1L << 16);
                }
                long targetByte = (targetWord * 2L) & 0xFFFFFFFFL;
                boolean inRange = targetByte >= part.flashStart() && targetByte <= part.flashEnd();
                String label = (i == 0) ? "Reset_Handler" : slot.name();
                entries.add(new AtmelVectorEntry(
                    slot, entryAddr, targetByte, raw,
                    AtmelVectorInstructionType.JMP, inRange, false, label
                ));
            } else {
                entries.add(new AtmelVectorEntry(
                    slot, entryAddr, 0L, raw,
                    AtmelVectorInstructionType.INVALID, false, false, "Invalid_Vector_" + i
                ));
            }
        }
    }

    private static void parseSamVectors(
            byte[] bytes, int offset, long tableBaseAddress, AtmelPartRecord part,
            List<AtmelVectorSlot> slots, int count, List<AtmelVectorEntry> entries,
            CancellationToken token) throws DiagnosticException {
        // Slot 0: Initial SP
        token.throwIfCancellationRequested();
        AtmelVectorSlot spSlot = slots.get(0);
        long initialSp = read32(bytes, offset);
        boolean spValid = initialSp >= part.ramStart() && initialSp <= (part.ramEnd() + 1L);
        entries.add(new AtmelVectorEntry(
            spSlot, tableBaseAddress, initialSp, initialSp,
            spValid ? AtmelVectorInstructionType.INITIAL_SP : AtmelVectorInstructionType.INVALID,
            spValid, false, "Initial_SP"
        ));

        // Slot 1: Reset handler
        token.throwIfCancellationRequested();
        AtmelVectorSlot resetSlot = slots.get(1);
        long resetVal = read32(bytes, offset + 4);
        boolean resetThumb = (resetVal & 1L) != 0L;
        long resetTarget = resetVal & ~1L;
        boolean resetInRange = resetTarget >= part.flashStart() && resetTarget <= part.flashEnd();
        boolean resetValid = resetThumb && resetInRange;
        entries.add(new AtmelVectorEntry(
            resetSlot, tableBaseAddress + 4L, resetTarget, resetVal,
            resetValid ? AtmelVectorInstructionType.THUMB_VECTOR : AtmelVectorInstructionType.INVALID,
            resetValid, false, "Reset_Handler"
        ));

        // Slots 2..N
        for (int i = 2; i < count; i++) {
            token.throwIfCancellationRequested();
            int entryOffset = offset + (i * 4);
            long entryAddr = tableBaseAddress + (i * 4L);
            AtmelVectorSlot slot = i < slots.size()
                ? slots.get(i)
                : new AtmelVectorSlot(i, "IRQ" + (i - 16), "IRQ " + (i - 16));

            long val = read32(bytes, entryOffset);
            boolean thumb = (val & 1L) != 0L;
            long target = val & ~1L;
            boolean inRange = target >= part.flashStart() && target <= part.flashEnd();
            boolean valid = thumb && inRange;

            entries.add(new AtmelVectorEntry(
                slot, entryAddr, target, val,
                valid ? AtmelVectorInstructionType.THUMB_VECTOR : AtmelVectorInstructionType.INVALID,
                valid, false, slot.name() + "_Handler"
            ));
        }
    }

    private static long read32(byte[] bytes, int offset) {
        return (bytes[offset] & 0xFFL)
            | ((bytes[offset + 1] & 0xFFL) << 8)
            | ((bytes[offset + 2] & 0xFFL) << 16)
            | ((bytes[offset + 3] & 0xFFL) << 24);
    }
}
