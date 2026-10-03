package io.github.rezabakhshi.embedra.targets.rp.pio;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.formats.rp.uf2.RpUf2Segment;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.OptionalLong;
import java.util.Set;

/**
 * Pure discovery scanner for Raspberry Pi PIO program structures (pio_program_t)
 * and standalone instruction arrays in firmware segments.
 */
public final class RpPioScanner {

    private final ParserLimits limits;

    public RpPioScanner() {
        this(ParserLimits.defaults());
    }

    public RpPioScanner(ParserLimits limits) {
        this.limits = Objects.requireNonNull(limits, "limits must not be null");
    }

    /**
     * Scans firmware segments for PIO programs.
     */
    public List<RpPioProgram> scan(List<RpUf2Segment> segments, CancellationToken token)
            throws DiagnosticException {
        return scan(segments, limits, token);
    }

    /**
     * Scans firmware segments for PIO programs under specific limits and cancellation token.
     */
    public static List<RpPioProgram> scan(
            List<RpUf2Segment> segments,
            ParserLimits limits,
            CancellationToken token) throws DiagnosticException {
        Objects.requireNonNull(segments, "segments must not be null");
        Objects.requireNonNull(limits, "limits must not be null");
        Objects.requireNonNull(token, "token must not be null");

        token.throwIfCancellationRequested();

        List<RpPioProgram> discovered = new ArrayList<>();
        Set<Long> coveredAddresses = new HashSet<>();

        // Pass 1: Discover pio_program_t structures
        for (RpUf2Segment segment : segments) {
            token.throwIfCancellationRequested();
            byte[] data = segment.data();
            long segBase = segment.targetAddress();

            if (data.length < 8) {
                continue;
            }

            ByteBuffer buf = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
            int maxOffset = data.length - 8;

            for (int offset = 0; offset <= maxOffset; offset += 4) {
                if (discovered.size() >= limits.maxObjects()) {
                    throw new DiagnosticException(Diagnostic.error(
                            DiagnosticCode.LIMIT_EXCEEDED,
                            "Discovered PIO programs exceed limit: " + limits.maxObjects()));
                }

                long structAddr = segBase + offset;
                long instrPtr = Integer.toUnsignedLong(buf.getInt(offset));

                // Instructions pointer must be 2-byte aligned and distinct from struct
                if ((instrPtr & 1) != 0 || instrPtr == structAddr) {
                    continue;
                }

                int length = Byte.toUnsignedInt(data[offset + 4]);
                int origin = data[offset + 5];
                int pioVersion = Byte.toUnsignedInt(data[offset + 6]);
                int usedGpio = Byte.toUnsignedInt(data[offset + 7]);

                if (length < 1 || length > 32) {
                    continue;
                }
                if (origin != -1 && (origin < 0 || origin > 31 || origin + length > 32)) {
                    continue;
                }
                // In Pico SDK: pio_version is 0 (RP2040) or 1 (RP2350). used_gpio_ranges bitmap <= 7.
                if (pioVersion > 1 || usedGpio > 7) {
                    continue;
                }

                // In Pico SDK / pioasm, instructions and struct are generated together in rodata:
                // ptr == struct_addr + 8 or struct_addr == ptr + roundUp4(length * 2).
                // If not adjacent, must be in close proximity (< 256 bytes) and relocatable (origin == -1).
                long dist = instrPtr - structAddr;
                boolean adjForward = (dist == 8);
                boolean adjBackward = (structAddr == instrPtr + ((length * 2 + 3) & ~3));
                if (!adjForward && !adjBackward) {
                    if (origin != -1 || Math.abs(dist) > 256) {
                        continue;
                    }
                }

                // If origin != -1 (fixed origin), length must be at least 2 to prevent matching int fields
                if (origin != -1 && length < 2) {
                    continue;
                }

                // Check if instrPtr points inside one of our segments
                RpUf2Segment targetSeg = findSegment(segments, instrPtr, length * 2);
                if (targetSeg == null) {
                    continue;
                }

                int targetOffset = (int) (instrPtr - targetSeg.targetAddress());
                if (targetOffset < 0 || targetOffset + (length * 2) > targetSeg.data().length) {
                    continue;
                }

                // Reject if the target array is a 32-bit pointer table
                if (isPointerTable(targetSeg.data(), targetOffset, length)) {
                    continue;
                }

                // Validate and decode instruction array
                List<RpPioInstruction> instrs = tryDecodeInstructions(
                        targetSeg.data(), targetOffset, length, RpPioConfig.withDefaults(length));
                if (instrs != null && !isAllTrivial(instrs)) {
                    RpPioConfig config = RpPioConfig.withDefaults(length);
                    String name = String.format("pio_program_0x%x", instrPtr);
                    RpPioProgram program = new RpPioProgram(
                            instrPtr, OptionalLong.of(structAddr), length, origin, instrs, config, name);
                    discovered.add(program);

                    for (int i = 0; i < length; i++) {
                        coveredAddresses.add(instrPtr + (i * 2L));
                    }
                    for (int i = 0; i < 8; i++) {
                        coveredAddresses.add(structAddr + i);
                    }
                }
            }
        }

        // Pass 2: Heuristic scan for standalone PIO instruction arrays (e.g. rp_pio_instructions)
        // ONLY execute if no structured pio_program_t instances were discovered,
        // preventing massive false-positives against CPU ISA code in standard Pico SDK firmware.
        if (discovered.isEmpty()) {
            for (RpUf2Segment segment : segments) {
                token.throwIfCancellationRequested();
                byte[] data = segment.data();
                long segBase = segment.targetAddress();

                if (data.length < 4) {
                    continue;
                }

                ByteBuffer buf = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
                int maxOffset = data.length - 4;

                for (int offset = 0; offset <= maxOffset; offset += 2) {
                    long addr = segBase + offset;
                    // Exclude flash boot2 and vector table headers (first 0x140 bytes of flash base)
                    if (segBase == 0x10000000L && offset < 0x140) {
                        continue;
                    }
                    if (coveredAddresses.contains(addr)) {
                        continue;
                    }

                    // Try to find a sequence of valid instructions ending with backward jmp loop
                    int runLen = 0;
                    int maxRun = Math.min(32, (data.length - offset) / 2);
                    boolean hasDistinctivePio = false;
                    boolean endsWithLoop = false;

                    for (int i = 0; i < maxRun; i++) {
                        long wordAddr = segBase + offset + (i * 2L);
                        if (coveredAddresses.contains(wordAddr)) {
                            break;
                        }
                        int w = Short.toUnsignedInt(buf.getShort(offset + (i * 2)));
                        if (!RpPioDisassembler.isValidInstruction(w)) {
                            break;
                        }
                        int op = (w >> 13) & 0x7;
                        if (isDistinctiveInstruction(op, w)) {
                            hasDistinctivePio = true;
                        }
                        runLen++;
                        if (op == 0) { // JMP
                            int cond = (w >> 5) & 0x7;
                            int target = w & 0x1F;
                            // Backward loop condition
                            if (cond == 0 && target <= i) {
                                endsWithLoop = true;
                                break;
                            }
                        }
                    }

                    if (runLen >= 2 && hasDistinctivePio && endsWithLoop) {
                        List<RpPioInstruction> instrs = tryDecodeInstructions(
                                data, offset, runLen, RpPioConfig.withDefaults(runLen));
                        if (instrs != null && !isAllTrivial(instrs)) {
                            String name = String.format("pio_instr_0x%x", addr);
                            RpPioConfig config = RpPioConfig.withDefaults(runLen);
                            RpPioProgram program = new RpPioProgram(
                                    addr, OptionalLong.empty(), runLen, -1, instrs, config, name);
                            discovered.add(program);

                            for (int i = 0; i < runLen; i++) {
                                coveredAddresses.add(addr + (i * 2L));
                            }
                            offset += (runLen * 2) - 2;
                        }
                    }
                }
            }
        }

        discovered.sort(Comparator.comparingLong(RpPioProgram::address));
        return List.copyOf(discovered);
    }

    private static boolean isDistinctiveInstruction(int op, int word) {
        switch (op) {
            case 1 -> { // WAIT
                int src = (word >> 5) & 0x3;
                return src == 0 || src == 1; // GPIO or PIN
            }
            case 2 -> { // IN
                int src = (word >> 5) & 0x7;
                return src == 0; // PINS
            }
            case 3 -> { // OUT
                int dst = (word >> 5) & 0x7;
                return dst == 0 || dst == 4; // PINS or PINDIRS
            }
            case 4 -> { // PUSH / PULL
                return (word & 0x1F) == 0;
            }
            case 7 -> { // SET
                int dst = (word >> 5) & 0x7;
                return dst == 0 || dst == 4; // PINS or PINDIRS
            }
            default -> {
                return false;
            }
        }
    }

    private static boolean isPointerTable(byte[] data, int offset, int length) {
        if (length < 2) {
            return false;
        }
        ByteBuffer buf = ByteBuffer.wrap(data, offset, length * 2).order(ByteOrder.LITTLE_ENDIAN);
        int highWordsCount = length / 2;
        int matchCount = 0;
        for (int i = 0; i < length; i++) {
            int w = Short.toUnsignedInt(buf.getShort());
            if (i % 2 == 1 && (w >= 0x1000 && w <= 0x1020)) {
                matchCount++;
            }
        }
        return matchCount > 0 && matchCount == highWordsCount;
    }

    private static RpUf2Segment findSegment(List<RpUf2Segment> segments, long address, int byteLength) {
        for (RpUf2Segment seg : segments) {
            if (address >= seg.targetAddress()
                    && address + byteLength <= seg.targetAddress() + seg.data().length) {
                return seg;
            }
        }
        return null;
    }

    private static List<RpPioInstruction> tryDecodeInstructions(
            byte[] data, int offset, int length, RpPioConfig config) {
        try {
            ByteBuffer buf = ByteBuffer.wrap(data, offset, length * 2).order(ByteOrder.LITTLE_ENDIAN);
            List<RpPioInstruction> list = new ArrayList<>(length);
            for (int i = 0; i < length; i++) {
                int w = Short.toUnsignedInt(buf.getShort());
                if (!RpPioDisassembler.isValidInstruction(w)) {
                    return null;
                }
                list.add(RpPioDisassembler.decode(w, config));
            }
            return list;
        } catch (Exception e) {
            return null;
        }
    }

    private static boolean isAllTrivial(List<RpPioInstruction> instrs) {
        boolean allZeros = true;
        boolean allOnes = true;
        for (RpPioInstruction i : instrs) {
            if (i.rawWord() != 0) {
                allZeros = false;
            }
            if (i.rawWord() != 0xFFFF) {
                allOnes = false;
            }
        }
        return allZeros || allOnes;
    }
}
