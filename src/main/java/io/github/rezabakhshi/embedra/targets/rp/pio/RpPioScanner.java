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

                long instrPtr = Integer.toUnsignedLong(buf.getInt(offset));
                int length = Byte.toUnsignedInt(data[offset + 4]);
                int origin = data[offset + 5];

                if (length < 1 || length > 32) {
                    continue;
                }
                if (origin != -1 && (origin < 0 || origin > 31 || origin + length > 32)) {
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

                // Validate and decode instruction array
                List<RpPioInstruction> instrs = tryDecodeInstructions(
                        targetSeg.data(), targetOffset, length, RpPioConfig.withDefaults(length));
                if (instrs != null && !isAllTrivial(instrs)) {
                    long structAddr = segBase + offset;
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

                // Try to find a sequence of valid instructions ending with jmp or loop
                int runLen = 0;
                int maxRun = Math.min(32, (data.length - offset) / 2);
                boolean hasDistinctivePio = false;
                boolean endsWithJmpOrWait = false;

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
                    if (op == 2 || op == 3 || op == 4 || op == 5 || op == 6 || op == 7) {
                        hasDistinctivePio = true;
                    }
                    runLen++;
                    if (op == 0) { // JMP
                        int target = w & 0x1F;
                        if (target <= i) {
                            endsWithJmpOrWait = true;
                            break;
                        }
                    } else if (op == 1 && (w & 0x7) == 0) { // WAIT
                        endsWithJmpOrWait = true;
                    }
                }

                if (runLen >= 2 && hasDistinctivePio && (endsWithJmpOrWait || runLen >= 4)) {
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

        discovered.sort(Comparator.comparingLong(RpPioProgram::address));
        return List.copyOf(discovered);
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
