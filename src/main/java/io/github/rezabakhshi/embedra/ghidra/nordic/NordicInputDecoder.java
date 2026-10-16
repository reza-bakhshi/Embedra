package io.github.rezabakhshi.embedra.ghidra.nordic;

import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.targets.nordic.softdevice.NordicSoftDeviceDetector;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.TreeMap;

/**
 * Validating decoder for Nordic Semiconductor input formats: raw BIN, Intel HEX, and ELF.
 * Enforces ParserLimits, strict checksum validation, non-overlapping records, and fail-closed bounds checking.
 */
public final class NordicInputDecoder {

    private static final int ELF_HEADER_SIZE = 52;

    private static final int ELF_PHDR_SIZE = 32;

    private static final int ELF_SHDR_SIZE = 40;

    private static final int EM_ARM = 40;

    private static final int PT_LOAD = 1;

    public record DecodedSegment(
        long address,
        byte[] data,
        String name
    ) {
        public DecodedSegment {
            Objects.requireNonNull(data, "data must not be null");
            Objects.requireNonNull(name, "name must not be null");
        }

        public long endAddress() {
            return address + data.length;
        }
    }

    public record DecodedNordicFirmware(
        String format,
        List<DecodedSegment> segments,
        long entryPoint,
        long minAddress,
        long maxAddress,
        Optional<Long> bootloaderAddress,
        Optional<Long> relocatedAppOffset
    ) {
        public DecodedNordicFirmware {
            Objects.requireNonNull(format, "format must not be null");
            segments = List.copyOf(Objects.requireNonNull(segments, "segments must not be null"));
            Objects.requireNonNull(bootloaderAddress, "bootloaderAddress must not be null");
            Objects.requireNonNull(relocatedAppOffset, "relocatedAppOffset must not be null");
        }
    }

    private NordicInputDecoder() {
    }

    /**
     * Determines format and decodes firmware segments with strict fail-closed validation.
     */
    public static DecodedNordicFirmware decode(byte[] input, ParserLimits limits) throws NordicMappingException {
        if (input == null || input.length == 0) {
            throw new NordicMappingException(DiagnosticCode.NORDIC_FORMAT_UNSUPPORTED, "Empty input file");
        }
        if (input.length > limits.maxInputBytes()) {
            throw new NordicMappingException(
                DiagnosticCode.NORDIC_FORMAT_UNSUPPORTED,
                "Input exceeds maxInputBytes limit (" + input.length + " > " + limits.maxInputBytes() + ")"
            );
        }

        // 1. Check ELF
        if (input.length >= 4 && input[0] == 0x7F && input[1] == 'E' && input[2] == 'L' && input[3] == 'F') {
            return decodeElf(input);
        }

        // 2. Check Intel HEX (starts with ':')
        if (isIntelHex(input)) {
            return decodeHex(input, limits);
        }

        // 3. Raw BIN
        return decodeRawBin(input);
    }

    private static boolean isIntelHex(byte[] input) {
        int i = 0;
        while (i < input.length && (input[i] == ' ' || input[i] == '\t' || input[i] == '\r' || input[i] == '\n')) {
            i++;
        }
        return i < input.length && input[i] == ':';
    }

    private static DecodedNordicFirmware decodeRawBin(byte[] input) throws NordicMappingException {
        if (input.length < 8) {
            throw new NordicMappingException(
                DiagnosticCode.NORDIC_FORMAT_UNSUPPORTED,
                "Raw binary image too small for Cortex-M vector table (" + input.length + " bytes)"
            );
        }

        ByteBuffer buf = ByteBuffer.wrap(input).order(ByteOrder.LITTLE_ENDIAN);
        long initialSp = buf.getInt(0) & 0xFFFFFFFFL;
        long resetVector = buf.getInt(4) & 0xFFFFFFFFL;

        // Verify Cortex-M vector requirements
        boolean validSp = (initialSp & 0xF0000000L) == 0x20000000L; // SP in SRAM aperture
        boolean thumbBit = (resetVector & 1L) != 0L;

        if (!validSp || !thumbBit) {
            throw new NordicMappingException(
                DiagnosticCode.NORDIC_VECTOR_TABLE_INVALID,
                "INVALID_INITIAL_SP_AND_EVEN_RESET_VECTOR: Initial SP 0x" + Long.toHexString(initialSp)
                    + " not in SRAM or Reset vector 0x" + Long.toHexString(resetVector) + " lacks Thumb bit"
            );
        }

        long entryPoint = resetVector & ~1L;
        DecodedSegment segment = new DecodedSegment(0x00000000L, input, "FLASH");
        return new DecodedNordicFirmware(
            "RAW_BINARY",
            List.of(segment),
            entryPoint,
            0x00000000L,
            input.length,
            Optional.empty(),
            Optional.empty()
        );
    }

    private static DecodedNordicFirmware decodeHex(byte[] input, ParserLimits limits) throws NordicMappingException {
        Map<Long, Byte> addressMap = new TreeMap<>();
        long upperAddress = 0L;
        Long startLinearAddress = null;

        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(new ByteArrayInputStream(input), StandardCharsets.US_ASCII))) {
            String line;
            int lineNumber = 0;
            while ((line = reader.readLine()) != null) {
                lineNumber++;
                line = line.trim();
                if (line.isEmpty()) {
                    continue;
                }
                if (!line.startsWith(":")) {
                    throw new NordicMappingException(
                        DiagnosticCode.NORDIC_INPUT_INVALID,
                        "Line " + lineNumber + " does not start with colon"
                    );
                }

                // Minimum line length for record without data: :LLAAAATTCC = 11 chars
                if (line.length() < 11) {
                    throw new NordicMappingException(
                        DiagnosticCode.NORDIC_INPUT_INVALID,
                        "TRUNCATED_INTEL_HEX_RECORD: Truncated record header on line " + lineNumber
                    );
                }

                int byteCount = parseHexByte(line, 1, lineNumber);
                int expectedLineLength = 1 + 2 + 4 + 2 + (byteCount * 2) + 2;
                if (line.length() < expectedLineLength) {
                    throw new NordicMappingException(
                        DiagnosticCode.NORDIC_INPUT_INVALID,
                        "TRUNCATED_INTEL_HEX_RECORD: Record byte count mismatch on line " + lineNumber
                    );
                }

                int addrOffset = parseHexWord(line, 3, lineNumber);
                int recordType = parseHexByte(line, 7, lineNumber);

                // Verify checksum
                int sum = byteCount + (addrOffset >> 8) + (addrOffset & 0xFF) + recordType;
                byte[] data = new byte[byteCount];
                for (int i = 0; i < byteCount; i++) {
                    int b = parseHexByte(line, 9 + (i * 2), lineNumber);
                    data[i] = (byte) b;
                    sum += b;
                }
                int checkByte = parseHexByte(line, 9 + (byteCount * 2), lineNumber);
                sum += checkByte;
                if ((sum & 0xFF) != 0) {
                    throw new NordicMappingException(
                        DiagnosticCode.NORDIC_INPUT_INVALID,
                        "CHECKSUM_MISMATCH: Invalid checksum on line " + lineNumber
                    );
                }

                switch (recordType) {
                    case 0x00 -> { // Data Record
                        long base = upperAddress + addrOffset;
                        for (int i = 0; i < byteCount; i++) {
                            long absAddr = base + i;
                            Byte existing = addressMap.putIfAbsent(absAddr, data[i]);
                            if (existing != null && existing != data[i]) {
                                throw new NordicMappingException(
                                    DiagnosticCode.NORDIC_MAPPING_CONFLICT,
                                    "OVERLAPPING_MEMORY_SEGMENTS: Overlapping Intel HEX records with conflicting"
                                        + " data at 0x" + Long.toHexString(absAddr)
                                );
                            }
                        }
                    }
                    case 0x01 -> { // EOF
                        // End of file
                    }
                    case 0x02 -> { // Extended Segment Address
                        if (byteCount != 2) {
                            throw new NordicMappingException(
                                DiagnosticCode.NORDIC_INPUT_INVALID,
                                "TRUNCATED_INTEL_HEX_RECORD: Extended Segment Address must be 2 bytes"
                            );
                        }
                        upperAddress = ((long) parseHexWord(line, 9, lineNumber)) << 4;
                    }
                    case 0x04 -> { // Extended Linear Address
                        if (byteCount != 2) {
                            throw new NordicMappingException(
                                DiagnosticCode.NORDIC_INPUT_INVALID,
                                "TRUNCATED_INTEL_HEX_RECORD: Extended Linear Address must be 2 bytes"
                            );
                        }
                        upperAddress = ((long) parseHexWord(line, 9, lineNumber)) << 16;
                    }
                    case 0x05 -> { // Start Linear Address
                        if (byteCount == 4) {
                            long ep = ((long) parseHexWord(line, 9, lineNumber) << 16)
                                | parseHexWord(line, 13, lineNumber);
                            startLinearAddress = ep;
                        }
                    }
                    default -> {
                        // Skip unsupported record types (e.g. start segment address)
                    }
                }
            }
        } catch (NordicMappingException e) {
            throw e;
        } catch (IOException e) {
            throw new NordicMappingException(DiagnosticCode.NORDIC_INPUT_INVALID, "Error reading HEX input", e);
        }

        if (addressMap.isEmpty()) {
            throw new NordicMappingException(DiagnosticCode.NORDIC_INPUT_INVALID, "No data records in Intel HEX");
        }

        // Group into contiguous segments
        List<DecodedSegment> segments = groupSegments(addressMap);
        long minAddr = addressMap.keySet().iterator().next();
        long maxAddr = minAddr;
        for (long a : addressMap.keySet()) {
            if (a > maxAddr) {
                maxAddr = a;
            }
        }

        // Check for UICR bootloader address
        Optional<Long> bootloaderAddr = Optional.empty();
        for (DecodedSegment seg : segments) {
            if (seg.address() == 0x10001000L && seg.data().length >= 0x18) {
                bootloaderAddr = NordicSoftDeviceDetector.discoverBootloaderAddress(seg.data());
            }
        }

        // Determine entry point and relocated app offset
        Optional<Long> relocatedAppOffset = Optional.empty();
        long entryPoint = 0L;

        if (startLinearAddress != null) {
            entryPoint = startLinearAddress & ~1L;
        } else {
            // Find base segment at 0x00000000L
            DecodedSegment baseSeg = findSegmentAt(segments, 0x00000000L);
            if (baseSeg != null && baseSeg.data().length >= 8) {
                ByteBuffer bb = ByteBuffer.wrap(baseSeg.data()).order(ByteOrder.LITTLE_ENDIAN);
                long mbrReset = bb.getInt(4) & 0xFFFFFFFFL;
                entryPoint = mbrReset & ~1L;

                // Check for SoftDevice / Relocated Application
                // If there's an application segment at S140 (0x27000), S132 (0x26000), or S112 (0x19000)
                DecodedSegment s140Seg = findSegmentAt(segments, NordicSoftDeviceDetector.S140_V7_APP_OFFSET);
                DecodedSegment s132Seg = findSegmentAt(segments, NordicSoftDeviceDetector.S132_V7_APP_OFFSET);
                DecodedSegment s112Seg = findSegmentAt(segments, NordicSoftDeviceDetector.S112_V7_APP_OFFSET);

                if (s140Seg != null && s140Seg.data().length >= 8) {
                    ByteBuffer appBb = ByteBuffer.wrap(s140Seg.data()).order(ByteOrder.LITTLE_ENDIAN);
                    entryPoint = (appBb.getInt(4) & 0xFFFFFFFFL) & ~1L;
                    relocatedAppOffset = Optional.of(NordicSoftDeviceDetector.S140_V7_APP_OFFSET);
                } else if (s132Seg != null && s132Seg.data().length >= 8) {
                    ByteBuffer appBb = ByteBuffer.wrap(s132Seg.data()).order(ByteOrder.LITTLE_ENDIAN);
                    entryPoint = (appBb.getInt(4) & 0xFFFFFFFFL) & ~1L;
                    relocatedAppOffset = Optional.of(NordicSoftDeviceDetector.S132_V7_APP_OFFSET);
                } else if (s112Seg != null && s112Seg.data().length >= 8) {
                    ByteBuffer appBb = ByteBuffer.wrap(s112Seg.data()).order(ByteOrder.LITTLE_ENDIAN);
                    entryPoint = (appBb.getInt(4) & 0xFFFFFFFFL) & ~1L;
                    relocatedAppOffset = Optional.of(NordicSoftDeviceDetector.S112_V7_APP_OFFSET);
                }
            } else if (!segments.isEmpty()) {
                // If no segment at 0x00000000, take the first segment's reset handler if >= 8 bytes
                DecodedSegment first = segments.get(0);
                long addr = first.address();
                boolean isNordicRegion = (addr < 0x00200000L)
                    || (addr >= 0x00FF0000L && addr <= 0x00FFFFFFL)
                    || (addr >= 0x10000000L && addr <= 0x10002000L);
                if (!isNordicRegion) {
                    throw new NordicMappingException(
                        DiagnosticCode.NORDIC_FORMAT_UNSUPPORTED,
                        "Segment address 0x" + Long.toHexString(addr) + " is outside Nordic memory map"
                    );
                }
                if (first.data().length >= 8) {
                    ByteBuffer bb = ByteBuffer.wrap(first.data()).order(ByteOrder.LITTLE_ENDIAN);
                    long reset = bb.getInt(4) & 0xFFFFFFFFL;
                    if ((reset & 1L) != 0L) {
                        entryPoint = reset & ~1L;
                    } else {
                        entryPoint = first.address();
                    }
                } else {
                    entryPoint = first.address();
                }
            }
        }

        return new DecodedNordicFirmware(
            "INTEL_HEX",
            segments,
            entryPoint,
            minAddr,
            maxAddr + 1L,
            bootloaderAddr,
            relocatedAppOffset
        );
    }

    private static List<DecodedSegment> groupSegments(Map<Long, Byte> addressMap) {
        List<DecodedSegment> segments = new ArrayList<>();
        List<Long> addresses = new ArrayList<>(addressMap.keySet());
        if (addresses.isEmpty()) {
            return segments;
        }

        long segStart = addresses.get(0);
        long expectedNext = segStart;
        ByteArrayBuffer currentBuf = new ByteArrayBuffer();

        for (long addr : addresses) {
            if (addr != expectedNext) {
                // Gap encountered: emit current segment
                segments.add(new DecodedSegment(segStart, currentBuf.toByteArray(), segmentNameFor(segStart)));
                segStart = addr;
                currentBuf = new ByteArrayBuffer();
            }
            currentBuf.append(addressMap.get(addr));
            expectedNext = addr + 1L;
        }

        if (currentBuf.size() > 0) {
            segments.add(new DecodedSegment(segStart, currentBuf.toByteArray(), segmentNameFor(segStart)));
        }

        return segments;
    }

    private static String segmentNameFor(long address) {
        if (address == 0x00000000L) {
            return "FLASH";
        }
        if (address == 0x00001000L) {
            return "SOFTDEVICE";
        }
        if (address == NordicSoftDeviceDetector.S140_V7_APP_OFFSET
                || address == NordicSoftDeviceDetector.S132_V7_APP_OFFSET
                || address == NordicSoftDeviceDetector.S112_V7_APP_OFFSET) {
            return "APPLICATION";
        }
        if (address == 0x10001000L) {
            return "UICR";
        }
        if (address == 0x01000000L) {
            return "NET_FLASH";
        }
        if (address == 0x00040000L) {
            return "NONSECURE_FLASH";
        }
        return "SEG_" + Long.toHexString(address).toUpperCase();
    }

    private static DecodedSegment findSegmentAt(List<DecodedSegment> segments, long address) {
        for (DecodedSegment seg : segments) {
            if (seg.address() == address) {
                return seg;
            }
        }
        return null;
    }

    private static DecodedNordicFirmware decodeElf(byte[] input) throws NordicMappingException {
        if (input.length < ELF_HEADER_SIZE) {
            throw new NordicMappingException(
                DiagnosticCode.NORDIC_INPUT_INVALID,
                "TRUNCATED_ELF_FILE: ELF header truncated (" + input.length + " bytes)"
            );
        }

        ByteBuffer buf = ByteBuffer.wrap(input).order(ByteOrder.LITTLE_ENDIAN);

        // Header check
        int elfClass = input[4] & 0xFF;
        int elfData = input[5] & 0xFF;
        if (elfClass != 1 || elfData != 1) {
            throw new NordicMappingException(
                DiagnosticCode.NORDIC_INPUT_INVALID,
                "TRUNCATED_ELF_FILE: Not a 32-bit little-endian ELF file"
            );
        }

        int machine = buf.getShort(18) & 0xFFFF;
        if (machine != EM_ARM) {
            throw new NordicMappingException(
                DiagnosticCode.NORDIC_INPUT_INVALID,
                "TRUNCATED_ELF_FILE: Machine is not ARM (expected 40, found " + machine + ")"
            );
        }

        long entryPoint = buf.getInt(24) & 0xFFFFFFFFL;
        long phoff = buf.getInt(28) & 0xFFFFFFFFL;
        long shoff = buf.getInt(32) & 0xFFFFFFFFL;
        int phentsize = buf.getShort(42) & 0xFFFF;
        int phnum = buf.getShort(44) & 0xFFFF;
        int shentsize = buf.getShort(46) & 0xFFFF;
        int shnum = buf.getShort(48) & 0xFFFF;

        // Strict bounds verification against file truncation
        long requiredPhdrBytes = phoff + ((long) phnum * phentsize);
        long requiredShdrBytes = shoff + ((long) shnum * shentsize);

        if (phoff > 0 && requiredPhdrBytes > input.length) {
            throw new NordicMappingException(
                DiagnosticCode.NORDIC_INPUT_INVALID,
                "TRUNCATED_ELF_FILE: ELF program headers truncated (" + input.length
                    + " < " + requiredPhdrBytes + ")"
            );
        }
        if (shoff > 0 && requiredShdrBytes > input.length) {
            throw new NordicMappingException(
                DiagnosticCode.NORDIC_INPUT_INVALID,
                "TRUNCATED_ELF_FILE: ELF section headers truncated (" + input.length
                    + " < " + requiredShdrBytes + ")"
            );
        }

        List<DecodedSegment> segments = new ArrayList<>();
        long minAddr = Long.MAX_VALUE;
        long maxAddr = 0L;

        for (int i = 0; i < phnum; i++) {
            int phOffset = (int) (phoff + (i * phentsize));
            if (phOffset + ELF_PHDR_SIZE > input.length) {
                throw new NordicMappingException(
                    DiagnosticCode.NORDIC_INPUT_INVALID,
                    "TRUNCATED_ELF_FILE: Program header " + i + " truncated"
                );
            }

            int pType = buf.getInt(phOffset);
            if (pType != PT_LOAD) {
                continue;
            }

            long pFileOffset = buf.getInt(phOffset + 4) & 0xFFFFFFFFL;
            long pVaddr = buf.getInt(phOffset + 8) & 0xFFFFFFFFL;
            long pFilesz = buf.getInt(phOffset + 16) & 0xFFFFFFFFL;

            if (pFileOffset + pFilesz > input.length) {
                throw new NordicMappingException(
                    DiagnosticCode.NORDIC_INPUT_INVALID,
                    "TRUNCATED_ELF_FILE: Segment " + i + " payload exceeds file length ("
                        + (pFileOffset + pFilesz) + " > " + input.length + ")"
                );
            }

            if (pFilesz > 0) {
                byte[] segData = Arrays.copyOfRange(input, (int) pFileOffset, (int) (pFileOffset + pFilesz));
                segments.add(new DecodedSegment(pVaddr, segData, segmentNameFor(pVaddr)));
                if (pVaddr < minAddr) {
                    minAddr = pVaddr;
                }
                if (pVaddr + pFilesz > maxAddr) {
                    maxAddr = pVaddr + pFilesz;
                }
            }
        }

        if (segments.isEmpty()) {
            throw new NordicMappingException(
                DiagnosticCode.NORDIC_INPUT_INVALID,
                "TRUNCATED_ELF_FILE: ELF contains no PT_LOAD segments"
            );
        }

        segments.sort(Comparator.comparingLong(DecodedSegment::address));
        long cleanEntryPoint = entryPoint & ~1L;

        return new DecodedNordicFirmware(
            "ELF",
            segments,
            cleanEntryPoint,
            minAddr,
            maxAddr,
            Optional.empty(),
            Optional.empty()
        );
    }

    private static int parseHexByte(String s, int offset, int line) throws NordicMappingException {
        try {
            return Integer.parseInt(s.substring(offset, offset + 2), 16);
        } catch (IndexOutOfBoundsException | NumberFormatException e) {
            throw new NordicMappingException(
                DiagnosticCode.NORDIC_INPUT_INVALID,
                "TRUNCATED_INTEL_HEX_RECORD: Invalid hex byte at offset " + offset + " on line " + line
            );
        }
    }

    private static int parseHexWord(String s, int offset, int line) throws NordicMappingException {
        try {
            return Integer.parseInt(s.substring(offset, offset + 4), 16);
        } catch (IndexOutOfBoundsException | NumberFormatException e) {
            throw new NordicMappingException(
                DiagnosticCode.NORDIC_INPUT_INVALID,
                "TRUNCATED_INTEL_HEX_RECORD: Invalid hex word at offset " + offset + " on line " + line
            );
        }
    }

    private static final class ByteArrayBuffer {
        private byte[] buf = new byte[128];

        private int count = 0;

        void append(byte b) {
            if (count >= buf.length) {
                buf = Arrays.copyOf(buf, buf.length * 2);
            }
            buf[count++] = b;
        }

        int size() {
            return count;
        }

        byte[] toByteArray() {
            return Arrays.copyOf(buf, count);
        }
    }
}
