package io.github.rezabakhshi.embedra.ghidra.atmel;

import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.TreeMap;

/**
 * Validating decoder for Atmel / Microchip input formats: raw BIN, Intel HEX, and ELF.
 * Enforces ParserLimits, strict checksum validation, non-overlapping records, and fail-closed bounds checking.
 */
public final class AtmelInputDecoder {

    private static final int ELF_HEADER_SIZE = 52;

    private static final int ELF_PHDR_SIZE = 32;

    private static final int EM_ARM = 40;

    private static final int EM_AVR = 83;

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

    public record DecodedAtmelFirmware(
        String format,
        List<DecodedSegment> segments,
        long entryPoint,
        long minAddress,
        long maxAddress,
        Optional<Long> bootloaderAddress,
        boolean isAvr,
        Optional<String> targetHint
    ) {
        public DecodedAtmelFirmware {
            Objects.requireNonNull(format, "format must not be null");
            segments = List.copyOf(Objects.requireNonNull(segments, "segments must not be null"));
            Objects.requireNonNull(bootloaderAddress, "bootloaderAddress must not be null");
            Objects.requireNonNull(targetHint, "targetHint must not be null");
        }
    }

    private AtmelInputDecoder() {
    }

    /**
     * Determines format and decodes firmware segments with strict fail-closed validation.
     */
    public static DecodedAtmelFirmware decode(byte[] input, ParserLimits limits) throws AtmelMappingException {
        if (input == null || input.length == 0) {
            throw new AtmelMappingException(DiagnosticCode.ATMEL_FORMAT_UNSUPPORTED, "Empty input file");
        }
        if (input.length > limits.maxInputBytes()) {
            throw new AtmelMappingException(
                DiagnosticCode.ATMEL_FORMAT_UNSUPPORTED,
                "Input exceeds maxInputBytes limit (" + input.length + " > " + limits.maxInputBytes() + ")"
            );
        }

        // 1. Check ELF (starts with 0x7F, 'E', 'L', 'F')
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

    private static DecodedAtmelFirmware decodeRawBin(byte[] input) throws AtmelMappingException {
        if (input.length < 8) {
            throw new AtmelMappingException(
                DiagnosticCode.ATMEL_INPUT_INVALID,
                "Raw binary image too small for vector table validation (" + input.length + " bytes)"
            );
        }

        ByteBuffer buf = ByteBuffer.wrap(input).order(ByteOrder.LITTLE_ENDIAN);
        long initialSp = buf.getInt(0) & 0xFFFFFFFFL;
        long resetVector = buf.getInt(4) & 0xFFFFFFFFL;

        // Check if candidate for ARM Cortex-M (SAM):
        // Either initial SP is in SRAM space (0x20000000..0x2FFFFFFF) or reset vector has Thumb bit and flash target
        boolean isArmCandidate = ((initialSp & 0xF0000000L) == 0x20000000L)
            || (((resetVector & 1L) == 1L) && resetVector < 0x01000000L && resetVector > 4L);

        if (isArmCandidate) {
            if (input.length < 64) {
                throw new AtmelMappingException(
                    DiagnosticCode.ATMEL_VECTOR_TABLE_TRUNCATED,
                    "[BINARY_TRUNCATED_VECTOR_TABLE] Binary length " + input.length
                        + " bytes is insufficient to hold minimal ARM Cortex-M vector table"
                );
            }

            boolean spInSram = (initialSp >= 0x20000000L && initialSp <= 0x20500000L);
            if (!spInSram) {
                throw new AtmelMappingException(
                    DiagnosticCode.ATMEL_VECTOR_TABLE_INVALID,
                    "[INVALID_INITIAL_SP] Initial stack pointer 0x" + Long.toHexString(initialSp).toUpperCase()
                        + " lies outside physical SRAM aperture"
                );
            }

            if ((resetVector & 1L) == 0L) {
                throw new AtmelMappingException(
                    DiagnosticCode.ATMEL_VECTOR_TABLE_INVALID,
                    "[INVALID_ARM_RESET_VECTOR] Reset vector lacks Thumb bit: 0x" + Long.toHexString(resetVector)
                );
            }

            long baseAddr = (resetVector >= 0x00800000L) ? 0x00800000L
                          : (resetVector >= 0x00400000L) ? 0x00400000L
                          : 0x00000000L;
            long entryPoint = resetVector & ~1L;
            Optional<Long> bootAddr = (baseAddr == 0x00800000L) ? Optional.of(0x00800000L) : Optional.empty();
            Optional<String> hint = (baseAddr >= 0x00400000L || initialSp == 0x20460000L)
                ? Optional.of("SAME70Q21") : Optional.of("SAMD21G18A");

            DecodedSegment seg = new DecodedSegment(baseAddr, input, "FLASH");
            return new DecodedAtmelFirmware(
                "RAW_BINARY",
                List.of(seg),
                entryPoint,
                baseAddr,
                baseAddr + input.length,
                bootAddr,
                false,
                hint
            );
        }

        // AVR binary validation: check RJMP or JMP at entry
        int b0 = input[0] & 0xFF;
        int b1 = input[1] & 0xFF;
        int rjmpOp = b0 | (b1 << 8);
        boolean isJmp = (b0 == 0x0C && (b1 & 0xFE) == 0x94);
        boolean isRjmp = ((rjmpOp & 0xF000) == 0xC000);

        if (!isJmp && !isRjmp) {
            throw new AtmelMappingException(
                DiagnosticCode.ATMEL_VECTOR_TABLE_INVALID,
                "[INVALID_AVR_VECTOR_TABLE] Vector table does not contain valid RJMP or JMP instructions"
            );
        }

        long entryPoint = 0x00000000L;
        if (isJmp && input.length >= 4) {
            int b2 = input[2] & 0xFF;
            int b3 = input[3] & 0xFF;
            long targetWord = b2 | (b3 << 8);
            if ((b1 & 0x01) != 0) {
                targetWord |= (1L << 16);
            }
            entryPoint = (targetWord * 2L) & 0xFFFFFFFFL;
        } else if (isRjmp) {
            int rel = rjmpOp & 0x0FFF;
            if ((rel & 0x0800) != 0) {
                rel |= ~0x0FFF;
            }
            long targetWord = 1L + rel;
            entryPoint = (targetWord * 2L) & 0xFFFFFFFFL;
        }

        Optional<String> hint = isRjmp ? Optional.of("ATtiny85")
            : (input.length > 65536 ? Optional.of("ATmega2560") : Optional.of("ATmega328P"));

        DecodedSegment seg = new DecodedSegment(0x00000000L, input, "FLASH");
        return new DecodedAtmelFirmware(
            "RAW_BINARY",
            List.of(seg),
            entryPoint,
            0x00000000L,
            (long) input.length,
            Optional.empty(),
            true,
            hint
        );
    }

    private static DecodedAtmelFirmware decodeHex(byte[] input, ParserLimits limits) throws AtmelMappingException {
        Map<Long, Byte> addressMap = new TreeMap<>();
        long upperAddress = 0L;
        Long startLinearAddress = null;
        boolean hasEof = false;

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
                    throw new AtmelMappingException(
                        DiagnosticCode.ATMEL_INPUT_INVALID,
                        "Line " + lineNumber + " does not start with colon"
                    );
                }

                // Minimum line length for record without data: :LLAAAATTCC = 11 chars
                if (line.length() < 11) {
                    throw new AtmelMappingException(
                        DiagnosticCode.ATMEL_INPUT_INVALID,
                        "[HEX_UNEXPECTED_EOF] File ended abruptly inside a data record on line " + lineNumber
                    );
                }

                int byteCount = parseHexByte(line, 1, lineNumber);
                int expectedLineLength = 1 + 2 + 4 + 2 + (byteCount * 2) + 2;
                if (line.length() < expectedLineLength) {
                    throw new AtmelMappingException(
                        DiagnosticCode.ATMEL_INPUT_INVALID,
                        "[HEX_UNEXPECTED_EOF] File ended abruptly inside a data record on line " + lineNumber
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
                    throw new AtmelMappingException(
                        DiagnosticCode.ATMEL_INPUT_INVALID,
                        "[HEX_CHECKSUM_MISMATCH] Record " + lineNumber + " checksum does not match computed checksum"
                    );
                }

                switch (recordType) {
                    case 0x00 -> { // Data Record
                        long base = upperAddress + addrOffset;
                        for (int i = 0; i < byteCount; i++) {
                            long absAddr = base + i;
                            Byte existing = addressMap.putIfAbsent(absAddr, data[i]);
                            if (existing != null && existing != data[i]) {
                                throw new AtmelMappingException(
                                    DiagnosticCode.ATMEL_MAPPING_CONFLICT,
                                    "[MEMORY_OVERLAP_CONFLICT] Address range 0x"
                                        + Long.toHexString(absAddr).toUpperCase()
                                        + " defined twice with conflicting values"
                                );
                            }
                        }
                    }
                    case 0x01 -> { // EOF
                        hasEof = true;
                    }
                    case 0x02 -> { // Extended Segment Address
                        if (byteCount != 2) {
                            throw new AtmelMappingException(
                                DiagnosticCode.ATMEL_INPUT_INVALID,
                                "[HEX_UNEXPECTED_EOF] Extended Segment Address must be 2 bytes"
                            );
                        }
                        upperAddress = ((long) parseHexWord(line, 9, lineNumber)) << 4;
                    }
                    case 0x04 -> { // Extended Linear Address
                        if (byteCount != 2) {
                            throw new AtmelMappingException(
                                DiagnosticCode.ATMEL_INPUT_INVALID,
                                "[HEX_UNEXPECTED_EOF] Extended Linear Address must be 2 bytes"
                            );
                        }
                        upperAddress = ((long) parseHexWord(line, 9, lineNumber)) << 16;
                    }
                    case 0x05 -> { // Start Linear Address
                        if (byteCount == 4) {
                            startLinearAddress = ((long) parseHexWord(line, 9, lineNumber) << 16)
                                | parseHexWord(line, 13, lineNumber);
                        }
                    }
                    default -> {
                    }
                }
            }
        } catch (AtmelMappingException e) {
            throw e;
        } catch (IOException e) {
            throw new AtmelMappingException(DiagnosticCode.ATMEL_INPUT_INVALID, "Error reading HEX input", e);
        }

        if (addressMap.isEmpty() || !hasEof) {
            throw new AtmelMappingException(
                DiagnosticCode.ATMEL_INPUT_INVALID,
                "[HEX_UNEXPECTED_EOF] File ended abruptly inside a data record or missing EOF record"
            );
        }

        List<DecodedSegment> segments = groupSegments(addressMap);
        long minAddr = addressMap.keySet().iterator().next();
        long maxAddr = minAddr;
        for (long a : addressMap.keySet()) {
            if (a > maxAddr) {
                maxAddr = a;
            }
        }

        // Check architecture and part hints
        boolean isAvr = true;
        Optional<Long> bootloaderAddr = Optional.empty();
        Optional<String> targetHint = Optional.empty();
        long entryPoint = (startLinearAddress != null) ? startLinearAddress : minAddr;

        // Check for Optiboot (0x7E00) or SAM-BA (0x00800000)
        for (DecodedSegment seg : segments) {
            if (seg.address() == 0x00007E00L) {
                bootloaderAddr = Optional.of(0x00007E00L);
                targetHint = Optional.of("ATmega328P");
            }
            if (seg.address() == 0x00800000L) {
                bootloaderAddr = Optional.of(0x00800000L);
                isAvr = false;
                targetHint = Optional.of("SAME70Q21");
            }
            if (seg.address() == 0x00400000L) {
                isAvr = false;
                targetHint = Optional.of("SAME70Q21");
            }
        }

        // If at 0x00000000, inspect vectors to distinguish SAM from AVR
        DecodedSegment baseSeg = findSegmentAt(segments, 0x00000000L);
        if (baseSeg != null && baseSeg.data().length >= 8) {
            ByteBuffer bb = ByteBuffer.wrap(baseSeg.data()).order(ByteOrder.LITTLE_ENDIAN);
            long sp = bb.getInt(0) & 0xFFFFFFFFL;
            long reset = bb.getInt(4) & 0xFFFFFFFFL;
            if ((sp & 0xF0000000L) == 0x20000000L && (reset & 1L) == 1L) {
                isAvr = false;
                entryPoint = reset & ~1L;
                targetHint = Optional.of("SAMD21G18A");
            } else {
                int b0 = baseSeg.data()[0] & 0xFF;
                int b1 = baseSeg.data()[1] & 0xFF;
                int rjmp = b0 | (b1 << 8);
                if ((rjmp & 0xF000) == 0xC000) {
                    targetHint = Optional.of("ATtiny85");
                } else if (maxAddr > 65536L) {
                    targetHint = Optional.of("ATmega2560");
                } else {
                    targetHint = Optional.of("ATmega328P");
                }
            }
        }

        if (maxAddr > 0x00900000L) {
            throw new AtmelMappingException(
                DiagnosticCode.ATMEL_TARGET_UNSUPPORTED,
                "[OUT_OF_BOUNDS_ADDRESS] Addresses exceed Atmel maximum physical flash aperture (0x"
                    + Long.toHexString(maxAddr) + " > 0x00900000)"
            );
        }

        boolean hasKnownBase = (baseSeg != null)
            || bootloaderAddr.isPresent()
            || (minAddr >= 0x00007000L && minAddr <= 0x00007F00L)
            || (minAddr >= 0x0003E000L && minAddr <= 0x0003FF00L)
            || (minAddr == 0x00400000L)
            || (minAddr == 0x00800000L)
            || (minAddr == 0x00080000L);

        if (!hasKnownBase) {
            throw new AtmelMappingException(
                DiagnosticCode.ATMEL_TARGET_UNSUPPORTED,
                "[UNKNOWN_IMAGE_BASE] Intel HEX does not match any known Atmel reset or bootloader base: 0x"
                    + Long.toHexString(minAddr)
            );
        }

        if (isAvr && maxAddr > 0x00040000L) {
            throw new AtmelMappingException(
                DiagnosticCode.ATMEL_TARGET_UNSUPPORTED,
                "[OUT_OF_BOUNDS_ADDRESS] AVR address space cannot exceed 256 KiB (0x"
                    + Long.toHexString(maxAddr) + " > 0x00040000)"
            );
        }

        return new DecodedAtmelFirmware(
            "INTEL_HEX",
            segments,
            entryPoint,
            minAddr,
            maxAddr + 1L,
            bootloaderAddr,
            isAvr,
            targetHint
        );
    }

    private static DecodedAtmelFirmware decodeElf(byte[] input) throws AtmelMappingException {
        if (input.length < ELF_HEADER_SIZE) {
            throw new AtmelMappingException(
                DiagnosticCode.ATMEL_INPUT_INVALID,
                "[ELF_TRUNCATED_HEADER] ELF file size " + input.length
                    + " bytes is smaller than 52-byte ELF32 header"
            );
        }

        ByteBuffer buf = ByteBuffer.wrap(input).order(ByteOrder.LITTLE_ENDIAN);

        int elfClass = input[4] & 0xFF;
        int elfData = input[5] & 0xFF;
        if (elfClass != 1 || elfData != 1) {
            throw new AtmelMappingException(
                DiagnosticCode.ATMEL_INPUT_INVALID,
                "Not a 32-bit little-endian ELF file"
            );
        }

        int machine = buf.getShort(18) & 0xFFFF;
        if (machine != EM_ARM && machine != EM_AVR) {
            throw new AtmelMappingException(
                DiagnosticCode.ATMEL_TARGET_UNSUPPORTED,
                "Unsupported ELF machine: " + machine + " (expected 83 for AVR or 40 for ARM)"
            );
        }

        boolean isAvr = (machine == EM_AVR);
        long entryPoint = buf.getInt(24) & 0xFFFFFFFFL;
        long phoff = buf.getInt(28) & 0xFFFFFFFFL;
        long shoff = buf.getInt(32) & 0xFFFFFFFFL;
        int phentsize = buf.getShort(42) & 0xFFFF;
        int phnum = buf.getShort(44) & 0xFFFF;
        int shentsize = buf.getShort(46) & 0xFFFF;
        int shnum = buf.getShort(48) & 0xFFFF;

        long requiredPhdrBytes = phoff + ((long) phnum * phentsize);
        long requiredShdrBytes = shoff + ((long) shnum * shentsize);

        if (phoff > 0 && requiredPhdrBytes > input.length) {
            throw new AtmelMappingException(
                DiagnosticCode.ATMEL_INPUT_INVALID,
                "[ELF_TRUNCATED_HEADER] ELF program headers truncated"
            );
        }
        if (shoff > 0 && requiredShdrBytes > input.length) {
            throw new AtmelMappingException(
                DiagnosticCode.ATMEL_INPUT_INVALID,
                "[ELF_TRUNCATED_HEADER] ELF section headers truncated"
            );
        }

        List<DecodedSegment> segments = new ArrayList<>();
        long minAddr = Long.MAX_VALUE;
        long maxAddr = 0L;
        Optional<Long> bootAddr = Optional.empty();

        for (int i = 0; i < phnum; i++) {
            int phOffset = (int) (phoff + (i * phentsize));
            if (phOffset + ELF_PHDR_SIZE > input.length) {
                throw new AtmelMappingException(
                    DiagnosticCode.ATMEL_INPUT_INVALID,
                    "[ELF_TRUNCATED_HEADER] Program header " + i + " truncated"
                );
            }

            int pType = buf.getInt(phOffset);
            if (pType != PT_LOAD) {
                continue;
            }

            long pFileOffset = buf.getInt(phOffset + 4) & 0xFFFFFFFFL;
            long pVaddr = buf.getInt(phOffset + 8) & 0xFFFFFFFFL;
            long pFilesz = buf.getInt(phOffset + 16) & 0xFFFFFFFFL;

            if (pFilesz == 0) {
                continue;
            }

            if (pFileOffset + pFilesz > input.length) {
                throw new AtmelMappingException(
                    DiagnosticCode.ATMEL_INPUT_INVALID,
                    "[ELF_TRUNCATED_HEADER] Program header " + i + " segment data exceeds file length"
                );
            }

            // Exclude AVR data segment offset (0x00800000 GNU ld convention)
            if (isAvr && pVaddr >= 0x00800000L) {
                continue;
            }

            byte[] segBytes = Arrays.copyOfRange(input, (int) pFileOffset, (int) (pFileOffset + pFilesz));
            String segName = segmentNameFor(pVaddr);
            segments.add(new DecodedSegment(pVaddr, segBytes, segName));

            if (pVaddr == 0x00007E00L) {
                bootAddr = Optional.of(0x00007E00L);
            } else if (pVaddr == 0x00800000L) {
                bootAddr = Optional.of(0x00800000L);
            }

            if (pVaddr < minAddr) {
                minAddr = pVaddr;
            }
            if (pVaddr + pFilesz > maxAddr) {
                maxAddr = pVaddr + pFilesz;
            }
        }

        if (segments.isEmpty()) {
            throw new AtmelMappingException(
                DiagnosticCode.ATMEL_INPUT_INVALID,
                "ELF contains no loadable executable program headers"
            );
        }

        Optional<String> hint;
        if (isAvr) {
            if (bootAddr.isPresent()) {
                hint = Optional.of("ATmega328P");
            } else if (maxAddr > 65536L) {
                hint = Optional.of("ATmega2560");
            } else if (maxAddr <= 8192L && segments.getFirst().data().length <= 256) {
                // Check if RJMP vector
                int b0 = segments.getFirst().data()[0] & 0xFF;
                int b1 = segments.getFirst().data()[1] & 0xFF;
                hint = (((b0 | (b1 << 8)) & 0xF000) == 0xC000)
                    ? Optional.of("ATtiny85") : Optional.of("ATmega328P");
            } else {
                hint = Optional.of("ATmega328P");
            }
        } else {
            hint = (minAddr >= 0x00400000L) ? Optional.of("SAME70Q21") : Optional.of("SAMD21G18A");
        }

        return new DecodedAtmelFirmware(
            "ELF",
            segments,
            entryPoint,
            minAddr,
            maxAddr,
            bootAddr,
            isAvr,
            hint
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
        if (address == 0x00007E00L) {
            return "BOOTLOADER";
        }
        if (address == 0x00400000L) {
            return "FLASH";
        }
        if (address == 0x00800000L) {
            return "SAM_BA_ROM";
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

    private static int parseHexByte(String line, int offset, int lineNum) throws AtmelMappingException {
        try {
            return Integer.parseInt(line.substring(offset, offset + 2), 16);
        } catch (Exception e) {
            throw new AtmelMappingException(
                DiagnosticCode.ATMEL_INPUT_INVALID,
                "Invalid hexadecimal byte on line " + lineNum + " at offset " + offset
            );
        }
    }

    private static int parseHexWord(String line, int offset, int lineNum) throws AtmelMappingException {
        try {
            return Integer.parseInt(line.substring(offset, offset + 4), 16);
        } catch (Exception e) {
            throw new AtmelMappingException(
                DiagnosticCode.ATMEL_INPUT_INVALID,
                "Invalid hexadecimal word on line " + lineNum + " at offset " + offset
            );
        }
    }

    private static final class ByteArrayBuffer {
        private byte[] buf = new byte[256];

        private int count = 0;

        void append(byte b) {
            if (count == buf.length) {
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
