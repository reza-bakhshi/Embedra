package io.github.rezabakhshi.embedra.targets.rp.binaryinfo;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.formats.rp.uf2.RpUf2Segment;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Pure, bounded parser for Raspberry Pi Pico SDK binary info blocks.
 */
public final class RpBinaryInfoParser {

    private static final int HEADER_SIZE = 20; // 5 words = 20 bytes

    private static final int MAX_NESTED_LIST_DEPTH = 5;

    private static final int MAX_STRING_LENGTH = 1024;

    private static int maxStringLength(ParserLimits limits) {
        return (int) Math.min(MAX_STRING_LENGTH, Math.min(Integer.MAX_VALUE, limits.maxAllocationBytes()));
    }

    public RpBinaryInfoResult parse(
            byte[] data,
            long baseAddress,
            ParserLimits limits,
            CancellationToken token) throws DiagnosticException {
        Objects.requireNonNull(data, "data must not be null");
        Objects.requireNonNull(limits, "limits must not be null");
        Objects.requireNonNull(token, "token must not be null");

        List<RpUf2Segment> segments = List.of(new RpUf2Segment(baseAddress, data, Optional.empty()));
        return parse(segments, limits, token);
    }

    public RpBinaryInfoResult parse(
            List<RpUf2Segment> segments,
            ParserLimits limits,
            CancellationToken token) throws DiagnosticException {
        Objects.requireNonNull(segments, "segments must not be null");
        Objects.requireNonNull(limits, "limits must not be null");
        Objects.requireNonNull(token, "token must not be null");

        token.throwIfCancellationRequested();
        MemoryView memory = new MemoryView(segments);

        // Scan for 0x7188dac3
        Long headerAddr = findHeaderAddress(memory, token);
        if (headerAddr == null) {
            return RpBinaryInfoResult.notPresent();
        }

        token.throwIfCancellationRequested();

        // Read header words
        long entriesStart = memory.readUint32(headerAddr + 4);
        long entriesEnd = memory.readUint32(headerAddr + 8);
        long markerEnd = memory.readUint32(headerAddr + 16);

        if (markerEnd != RpBinaryInfoMarker.MARKER_END) {
            return RpBinaryInfoResult.notPresent();
        }

        if (entriesEnd < entriesStart || (entriesEnd - entriesStart) % 4 != 0) {
            throw new DiagnosticException(
                    Diagnostic.error(DiagnosticCode.RP_BINARY_INFO_INVALID,
                            "Malformed Pico SDK binary info table bounds: 0x" + Long.toHexString(entriesStart)
                                    + " to 0x" + Long.toHexString(entriesEnd)));
        }

        long entryCount = (entriesEnd - entriesStart) / 4;
        if (entryCount > limits.maxObjects() || entryCount > 2048) {
            throw new DiagnosticException(
                    Diagnostic.error(DiagnosticCode.LIMIT_EXCEEDED,
                            "Pico SDK binary info entry count (" + entryCount + ") exceeds limit"));
        }

        List<String> diagnostics = new ArrayList<>();
        List<Long> entryPointers = new ArrayList<>();
        for (long addr = entriesStart; addr < entriesEnd; addr += 4) {
            token.throwIfCancellationRequested();
            Long entryPtr = memory.readUint32Safe(addr);
            if (entryPtr != null && entryPtr != 0) {
                entryPointers.add(entryPtr);
            }
        }

        return parseEntries(memory, headerAddr, entryPointers, limits, token, diagnostics);
    }

    private Long findHeaderAddress(MemoryView memory, CancellationToken token) throws DiagnosticException {
        for (RpUf2Segment segment : memory.segments) {
            byte[] data = segment.data();
            long target = segment.targetAddress();
            int len = data.length;

            for (int i = 0; i + HEADER_SIZE <= len; i += 4) {
                if ((i & 0xFFF) == 0) {
                    token.throwIfCancellationRequested();
                }
                long mStart = readUint32(data, i);
                if (mStart == RpBinaryInfoMarker.MARKER_START) {
                    long mEnd = readUint32(data, i + 16);
                    if (mEnd == RpBinaryInfoMarker.MARKER_END) {
                        return target + i;
                    }
                }
            }
        }
        return null;
    }

    private RpBinaryInfoResult parseEntries(
            MemoryView memory,
            long headerAddress,
            List<Long> entryPointers,
            ParserLimits limits,
            CancellationToken token,
            List<String> diagnostics) throws DiagnosticException {

        String programName = null;
        String programVersion = null;
        String programBuildDate = null;
        String programUrl = null;
        String programDescription = null;
        String sdkVersion = null;
        String picoBoard = null;
        String boot2Name = null;
        Long binaryEnd = null;

        List<String> features = new ArrayList<>();
        List<String> buildAttributes = new ArrayList<>();
        List<RpBinaryInfoPin> pins = new ArrayList<>();
        List<RpBinaryInfoBlockDevice> blockDevices = new ArrayList<>();

        List<Long> workQueue = new ArrayList<>(entryPointers);
        int parsedCount = 0;

        while (!workQueue.isEmpty()) {
            token.throwIfCancellationRequested();
            if (++parsedCount > 4096) {
                diagnostics.add("Binary info entry queue limit reached");
                break;
            }

            long entryAddr = workQueue.remove(0);
            Integer type = memory.readUint16Safe(entryAddr);
            Integer tag = memory.readUint16Safe(entryAddr + 2);
            if (type == null || tag == null) {
                diagnostics.add("Unmapped binary info entry pointer at 0x" + Long.toHexString(entryAddr));
                continue;
            }

            switch (type) {
                case RpBinaryInfoMarker.TYPE_ID_AND_STRING -> {
                    Long id = memory.readUint32Safe(entryAddr + 4);
                    Long strPtr = memory.readUint32Safe(entryAddr + 8);
                    if (id != null && strPtr != null) {
                        String value = memory.readStringSafe(strPtr, maxStringLength(limits));
                        if (value != null) {
                            if (id == RpBinaryInfoMarker.ID_RP_PROGRAM_NAME) {
                                programName = value;
                            } else if (id == RpBinaryInfoMarker.ID_RP_PROGRAM_VERSION_STRING) {
                                programVersion = value;
                            } else if (id == RpBinaryInfoMarker.ID_RP_PROGRAM_BUILD_DATE_STRING) {
                                programBuildDate = value;
                            } else if (id == RpBinaryInfoMarker.ID_RP_PROGRAM_URL) {
                                programUrl = value;
                            } else if (id == RpBinaryInfoMarker.ID_RP_PROGRAM_DESCRIPTION) {
                                programDescription = value;
                            } else if (id == RpBinaryInfoMarker.ID_RP_SDK_VERSION) {
                                sdkVersion = value;
                            } else if (id == RpBinaryInfoMarker.ID_RP_PICO_BOARD) {
                                picoBoard = value;
                            } else if (id == RpBinaryInfoMarker.ID_RP_BOOT2_NAME) {
                                boot2Name = value;
                            } else if (id == RpBinaryInfoMarker.ID_RP_PROGRAM_FEATURE) {
                                features.add(value);
                            } else if (id == RpBinaryInfoMarker.ID_RP_PROGRAM_BUILD_ATTRIBUTE) {
                                buildAttributes.add(value);
                            }
                        } else {
                            diagnostics.add("String pointer 0x" + Long.toHexString(strPtr) + " could not be resolved");
                        }
                    }
                }
                case RpBinaryInfoMarker.TYPE_ID_AND_INT -> {
                    Long id = memory.readUint32Safe(entryAddr + 4);
                    Long intVal = memory.readUint32Safe(entryAddr + 8);
                    if (id != null && intVal != null) {
                        if (id == RpBinaryInfoMarker.ID_RP_BINARY_END) {
                            binaryEnd = intVal;
                        }
                    }
                }
                case RpBinaryInfoMarker.TYPE_PINS_WITH_NAME -> {
                    Long pinMask = memory.readUint32Safe(entryAddr + 4);
                    Long labelPtr = memory.readUint32Safe(entryAddr + 8);
                    if (pinMask != null && labelPtr != null) {
                        String label = memory.readStringSafe(labelPtr, maxStringLength(limits));
                        pins.add(new RpBinaryInfoPin(pinMask, label != null ? label : "Unknown", Optional.empty()));
                    }
                }
                case RpBinaryInfoMarker.TYPE_PINS64_WITH_NAME -> {
                    Long pinMask = memory.readUint64Safe(entryAddr + 4);
                    Long labelPtr = memory.readUint32Safe(entryAddr + 12);
                    if (pinMask != null && labelPtr != null) {
                        String label = memory.readStringSafe(labelPtr, maxStringLength(limits));
                        pins.add(new RpBinaryInfoPin(pinMask, label != null ? label : "Unknown", Optional.empty()));
                    }
                }
                case RpBinaryInfoMarker.TYPE_PINS_WITH_FUNC -> {
                    Long encoding = memory.readUint32Safe(entryAddr + 4);
                    if (encoding != null) {
                        int func = (int) ((encoding >> 3) & 0x0F);
                        long pinMask = decodePins(encoding);
                        pins.add(new RpBinaryInfoPin(pinMask, "FUNC_" + func, Optional.of(func)));
                    }
                }
                case RpBinaryInfoMarker.TYPE_PINS64_WITH_FUNC -> {
                    Long encoding = memory.readUint64Safe(entryAddr + 4);
                    if (encoding != null) {
                        int func = (int) ((encoding >> 3) & 0x1F);
                        long pinMask = decodePins64(encoding);
                        pins.add(new RpBinaryInfoPin(pinMask, "FUNC_" + func, Optional.of(func)));
                    }
                }
                case RpBinaryInfoMarker.TYPE_BLOCK_DEVICE -> {
                    Long namePtr = memory.readUint32Safe(entryAddr + 4);
                    Long address = memory.readUint32Safe(entryAddr + 8);
                    Long size = memory.readUint32Safe(entryAddr + 12);
                    Integer flags = memory.readUint16Safe(entryAddr + 20);
                    if (address != null && size != null) {
                        String name = namePtr != null ? memory.readStringSafe(namePtr, maxStringLength(limits)) : "";
                        blockDevices.add(new RpBinaryInfoBlockDevice(
                                name != null ? name : "block_dev",
                                address,
                                size,
                                flags != null ? flags : 0));
                    }
                }
                case RpBinaryInfoMarker.TYPE_BINARY_INFO_LIST_ZERO_TERMINATED -> {
                    Long listPtr = memory.readUint32Safe(entryAddr + 4);
                    if (listPtr != null && listPtr != 0) {
                        for (int i = 0; i < 256; i++) {
                            Long nestedEntry = memory.readUint32Safe(listPtr + i * 4L);
                            if (nestedEntry == null || nestedEntry == 0) {
                                break;
                            }
                            workQueue.add(nestedEntry);
                        }
                    }
                }
                default -> {
                    // Other types safely ignored or future extension
                }
            }
        }

        return new RpBinaryInfoResult(
                true,
                headerAddress,
                Optional.ofNullable(programName),
                Optional.ofNullable(programVersion),
                Optional.ofNullable(programBuildDate),
                Optional.ofNullable(programUrl),
                Optional.ofNullable(programDescription),
                Optional.ofNullable(sdkVersion),
                Optional.ofNullable(picoBoard),
                Optional.ofNullable(boot2Name),
                Optional.ofNullable(binaryEnd),
                features,
                buildAttributes,
                pins,
                blockDevices,
                diagnostics);
    }

    private static long decodePins(long encoding) {
        int encType = (int) (encoding & 0x07);
        if (encType == 1) { // Range
            int plo = (int) ((encoding >> 7) & 0x1F);
            int phi = (int) ((encoding >> 12) & 0x1F);
            long mask = 0;
            for (int p = plo; p <= phi && p < 32; p++) {
                mask |= (1L << p);
            }
            return mask;
        } else if (encType == 2) { // Individual
            long mask = 0;
            for (int i = 0; i < 5; i++) {
                int pin = (int) ((encoding >> (7 + i * 5)) & 0x1F);
                mask |= (1L << pin);
            }
            return mask;
        }
        return 0;
    }

    private static long decodePins64(long encoding) {
        int encType = (int) (encoding & 0x07);
        if (encType == 1) { // Range
            int plo = (int) ((encoding >> 8) & 0xFF);
            int phi = (int) ((encoding >> 16) & 0xFF);
            long mask = 0;
            for (int p = plo; p <= phi && p < 64; p++) {
                mask |= (1L << p);
            }
            return mask;
        } else if (encType == 2) { // Individual
            long mask = 0;
            for (int i = 0; i < 7; i++) {
                int pin = (int) ((encoding >> (8 + i * 8)) & 0xFF);
                if (pin < 64) {
                    mask |= (1L << pin);
                }
            }
            return mask;
        }
        return 0;
    }

    private static long readUint32(byte[] data, int offset) {
        return (data[offset] & 0xFFL)
                | ((data[offset + 1] & 0xFFL) << 8)
                | ((data[offset + 2] & 0xFFL) << 16)
                | ((data[offset + 3] & 0xFFL) << 24);
    }

    private static final class MemoryView {
        private final List<RpUf2Segment> segments;

        private MemoryView(List<RpUf2Segment> segments) {
            this.segments = segments;
        }

        private RpUf2Segment findSegment(long address) {
            for (RpUf2Segment s : segments) {
                if (address >= s.targetAddress() && address < s.endAddress()) {
                    return s;
                }
            }
            return null;
        }

        private long readUint32(long address) {
            RpUf2Segment s = findSegment(address);
            if (s == null || address + 4 > s.endAddress()) {
                throw new IndexOutOfBoundsException("Address 0x" + Long.toHexString(address) + " outside memory");
            }
            int offset = (int) (address - s.targetAddress());
            return RpBinaryInfoParser.readUint32(s.data(), offset);
        }

        private Long readUint32Safe(long address) {
            RpUf2Segment s = findSegment(address);
            if (s == null || address + 4 > s.endAddress()) {
                return null;
            }
            int offset = (int) (address - s.targetAddress());
            return RpBinaryInfoParser.readUint32(s.data(), offset);
        }

        private Integer readUint16Safe(long address) {
            RpUf2Segment s = findSegment(address);
            if (s == null || address + 2 > s.endAddress()) {
                return null;
            }
            int offset = (int) (address - s.targetAddress());
            byte[] data = s.data();
            return (data[offset] & 0xFF) | ((data[offset + 1] & 0xFF) << 8);
        }

        private Long readUint64Safe(long address) {
            Long low = readUint32Safe(address);
            Long high = readUint32Safe(address + 4);
            if (low == null || high == null) {
                return null;
            }
            return low | (high << 32);
        }

        private String readStringSafe(long address, int maxLength) {
            RpUf2Segment s = findSegment(address);
            if (s == null) {
                return null;
            }
            int offset = (int) (address - s.targetAddress());
            byte[] data = s.data();
            int end = offset;
            while (end < data.length && data[end] != 0 && (end - offset) < maxLength) {
                end++;
            }
            if (end == offset) {
                return "";
            }
            return new String(data, offset, end - offset, StandardCharsets.UTF_8);
        }
    }
}
