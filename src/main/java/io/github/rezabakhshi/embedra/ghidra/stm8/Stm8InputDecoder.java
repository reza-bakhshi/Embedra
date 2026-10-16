package io.github.rezabakhshi.embedra.ghidra.stm8;

import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Validating decoder for STM8 input formats: raw BIN, Intel HEX, Motorola S-Record, and ELF.
 * Enforces ParserLimits, strict checksum validation, non-overlapping records, and fail-closed bounds checking.
 */
public final class Stm8InputDecoder {

    private static final long FLASH_BASE = 0x008000L;

    private static final int MAX_FLASH_BYTES = 128 * 1024; // STM8 max program flash 128 KiB

    private static final long FLASH_END = FLASH_BASE + MAX_FLASH_BYTES;

    public record DecodedFirmware(
        String format,
        byte[] flashBytes,
        long entryPoint,
        long minAddress,
        long maxAddress
    ) { }

    private Stm8InputDecoder() { }

    /**
     * Determines format and decodes flash bytes into contiguous buffer for Flash mapping.
     */
    public static DecodedFirmware decode(byte[] input, ParserLimits limits) throws Stm8MappingException {
        if (input == null || input.length == 0) {
            throw new Stm8MappingException(DiagnosticCode.STM8_FORMAT_UNSUPPORTED, "Empty input file");
        }
        if (input.length > limits.maxInputBytes()) {
            throw new Stm8MappingException(
                DiagnosticCode.STM8_FORMAT_UNSUPPORTED,
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

        // 3. Check Motorola S-Record (starts with 'S')
        if (isSRecord(input)) {
            return decodeSRecord(input, limits);
        }

        // 4. Raw BIN
        return decodeRawBin(input);
    }

    private static boolean isIntelHex(byte[] input) {
        int i = 0;
        while (i < input.length && (input[i] == ' ' || input[i] == '\t' || input[i] == '\r' || input[i] == '\n')) {
            i++;
        }
        return i < input.length && input[i] == ':';
    }

    private static boolean isSRecord(byte[] input) {
        int i = 0;
        while (i < input.length && (input[i] == ' ' || input[i] == '\t' || input[i] == '\r' || input[i] == '\n')) {
            i++;
        }
        return i < input.length && input[i] == 'S';
    }

    private static DecodedFirmware decodeRawBin(byte[] input) throws Stm8MappingException {
        if (input.length > MAX_FLASH_BYTES) {
            throw new Stm8MappingException(
                DiagnosticCode.STM8_FORMAT_UNSUPPORTED,
                "Raw binary image (" + input.length + " bytes) exceeds maximum STM8 flash size ("
                    + MAX_FLASH_BYTES + ")"
            );
        }
        long entryPoint = FLASH_BASE;
        if (input.length >= 4 && (input[0] & 0xFF) == 0x82) {
            entryPoint = ((input[1] & 0xFFL) << 16) | ((input[2] & 0xFFL) << 8) | (input[3] & 0xFFL);
        }
        return new DecodedFirmware("RAW_BINARY", input, entryPoint, FLASH_BASE, FLASH_BASE + input.length);
    }

    private static DecodedFirmware decodeElf(byte[] input) throws Stm8MappingException {
        if (input.length < 52) {
            throw new Stm8MappingException(DiagnosticCode.STM8_FORMAT_UNSUPPORTED, "Malformed ELF header");
        }
        boolean isBigEndian = input[5] == 2;
        long entry = read32(input, 24, isBigEndian);
        int phOff = (int) read32(input, 28, isBigEndian);
        int phEntSize = read16(input, 42, isBigEndian);
        int phNum = read16(input, 44, isBigEndian);

        if (phOff < 0 || phOff >= input.length || phNum <= 0) {
            throw new Stm8MappingException(DiagnosticCode.STM8_FORMAT_UNSUPPORTED, "ELF contains no program headers");
        }

        byte[] memory = new byte[MAX_FLASH_BYTES];
        boolean[] touched = new boolean[MAX_FLASH_BYTES];
        long minAddr = Long.MAX_VALUE;
        long maxAddr = 0;

        for (int i = 0; i < phNum; i++) {
            int entryOffset = phOff + i * phEntSize;
            if (entryOffset + 32 > input.length) {
                break;
            }
            int type = (int) read32(input, entryOffset, isBigEndian);
            if (type != 1) { // PT_LOAD
                continue;
            }
            int offset = (int) read32(input, entryOffset + 4, isBigEndian);
            long vaddr = read32(input, entryOffset + 8, isBigEndian);
            int filesz = (int) read32(input, entryOffset + 16, isBigEndian);

            if (offset < 0 || offset + filesz > input.length || filesz < 0) {
                throw new Stm8MappingException(
                    DiagnosticCode.STM8_FORMAT_UNSUPPORTED, "ELF segment exceeds input bounds");
            }

            for (int b = 0; b < filesz; b++) {
                long targetAddr = vaddr + b;
                if (targetAddr >= FLASH_BASE && targetAddr < FLASH_END) {
                    int slot = (int) (targetAddr - FLASH_BASE);
                    if (touched[slot] && memory[slot] != input[offset + b]) {
                        throw new Stm8MappingException(
                            DiagnosticCode.STM8_FORMAT_UNSUPPORTED,
                            String.format("ELF overlapping segment conflict at address 0x%06X", targetAddr)
                        );
                    }
                    memory[slot] = input[offset + b];
                    touched[slot] = true;
                    if (targetAddr < minAddr) {
                        minAddr = targetAddr;
                    }
                    if (targetAddr + 1 > maxAddr) {
                        maxAddr = targetAddr + 1;
                    }
                }
            }
        }

        if (maxAddr <= FLASH_BASE) {
            throw new Stm8MappingException(
                DiagnosticCode.STM8_FORMAT_UNSUPPORTED,
                "ELF contains no loadable sections in STM8 flash space [0x008000, 0x028000)"
            );
        }

        int flashSize = (int) (maxAddr - FLASH_BASE);
        byte[] flashBytes = Arrays.copyOf(memory, flashSize);
        return new DecodedFirmware("ELF", flashBytes, entry, minAddr, maxAddr);
    }

    private static DecodedFirmware decodeHex(byte[] input, ParserLimits limits) throws Stm8MappingException {
        byte[] memory = new byte[MAX_FLASH_BYTES];
        boolean[] touched = new boolean[MAX_FLASH_BYTES];
        long minAddr = Long.MAX_VALUE;
        long maxAddr = 0;
        long entryPoint = 0;
        long base = 0;
        int lineCount = 0;

        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(new ByteArrayInputStream(input), StandardCharsets.US_ASCII))) {
            String line;
            while ((line = reader.readLine()) != null) {
                lineCount++;
                if (lineCount > limits.maxObjects()) {
                    throw new Stm8MappingException(
                        DiagnosticCode.STM8_FORMAT_UNSUPPORTED,
                        "Intel HEX exceeds object count limit"
                    );
                }
                line = line.trim();
                if (line.isEmpty()) {
                    continue;
                }
                if (!line.startsWith(":")) {
                    throw new Stm8MappingException(
                        DiagnosticCode.STM8_FORMAT_UNSUPPORTED,
                        "Invalid Intel HEX line format at line " + lineCount
                    );
                }

                byte[] record = parseHexRecord(line, lineCount);
                int length = record[0] & 0xFF;
                int addressOffset = ((record[1] & 0xFF) << 8) | (record[2] & 0xFF);
                int type = record[3] & 0xFF;

                switch (type) {
                    case 0x00 -> { // DATA
                        for (int i = 0; i < length; i++) {
                            long targetAddr = base + addressOffset + i;
                            byte b = record[4 + i];
                            if (targetAddr >= FLASH_BASE && targetAddr < FLASH_END) {
                                int slot = (int) (targetAddr - FLASH_BASE);
                                if (touched[slot] && memory[slot] != b) {
                                    throw new Stm8MappingException(
                                        DiagnosticCode.STM8_FORMAT_UNSUPPORTED,
                                        String.format(
                                            "Conflicting records at 0x%06X (line %d)",
                                            targetAddr, lineCount)
                                    );
                                }
                                memory[slot] = b;
                                touched[slot] = true;
                                if (targetAddr < minAddr) {
                                    minAddr = targetAddr;
                                }
                                if (targetAddr + 1 > maxAddr) {
                                    maxAddr = targetAddr + 1;
                                }
                            }
                        }
                    }
                    case 0x01 -> { // EOF
                        // Handled
                    }
                    case 0x02 -> { // Extended Segment Address
                        if (length != 2) {
                            throw new Stm8MappingException(
                                DiagnosticCode.STM8_FORMAT_UNSUPPORTED, "Malformed segment address record");
                        }
                        base = (((record[4] & 0xFF) << 8) | (record[5] & 0xFF)) << 4;
                    }
                    case 0x04 -> { // Extended Linear Address
                        if (length != 2) {
                            throw new Stm8MappingException(
                                DiagnosticCode.STM8_FORMAT_UNSUPPORTED, "Malformed linear address record");
                        }
                        base = (long) (((record[4] & 0xFF) << 8) | (record[5] & 0xFF)) << 16;
                    }
                    case 0x05 -> { // Start Linear Address
                        if (length == 4) {
                            entryPoint = ((record[4] & 0xFFL) << 24)
                                | ((record[5] & 0xFFL) << 16)
                                | ((record[6] & 0xFFL) << 8)
                                | (record[7] & 0xFFL);
                        }
                    }
                    default -> {
                        // ignore unhandled record types
                    }
                }
            }
        } catch (IOException e) {
            throw new Stm8MappingException(
                DiagnosticCode.STM8_FORMAT_UNSUPPORTED, "Failed to read Intel HEX: " + e.getMessage(), e);
        }

        if (maxAddr <= FLASH_BASE) {
            throw new Stm8MappingException(
                DiagnosticCode.STM8_FORMAT_UNSUPPORTED,
                "Intel HEX contains no records in STM8 flash space [0x008000, 0x028000)"
            );
        }

        int flashSize = (int) (maxAddr - FLASH_BASE);
        byte[] flashBytes = Arrays.copyOf(memory, flashSize);
        if (entryPoint == 0 && flashSize >= 4 && (flashBytes[0] & 0xFF) == 0x82) {
            entryPoint = ((flashBytes[1] & 0xFFL) << 16) | ((flashBytes[2] & 0xFFL) << 8) | (flashBytes[3] & 0xFFL);
        }
        return new DecodedFirmware("INTEL_HEX", flashBytes, entryPoint, minAddr, maxAddr);
    }

    private static DecodedFirmware decodeSRecord(byte[] input, ParserLimits limits) throws Stm8MappingException {
        byte[] memory = new byte[MAX_FLASH_BYTES];
        boolean[] touched = new boolean[MAX_FLASH_BYTES];
        long minAddr = Long.MAX_VALUE;
        long maxAddr = 0;
        long entryPoint = 0;
        int lineCount = 0;

        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(new ByteArrayInputStream(input), StandardCharsets.US_ASCII))) {
            String line;
            while ((line = reader.readLine()) != null) {
                lineCount++;
                if (lineCount > limits.maxObjects()) {
                    throw new Stm8MappingException(
                        DiagnosticCode.STM8_FORMAT_UNSUPPORTED,
                        "Motorola S-Record exceeds object count limit"
                    );
                }
                line = line.trim();
                if (line.isEmpty()) {
                    continue;
                }
                if (!line.startsWith("S") || line.length() < 4) {
                    throw new Stm8MappingException(
                        DiagnosticCode.STM8_FORMAT_UNSUPPORTED,
                        "Invalid S-Record line at line " + lineCount
                    );
                }

                char typeChar = line.charAt(1);
                byte[] bytes = parseHexBytes(line.substring(2));
                int count = bytes[0] & 0xFF;
                if (bytes.length != count + 1) {
                    throw new Stm8MappingException(
                        DiagnosticCode.STM8_FORMAT_UNSUPPORTED,
                        "Corrupted S-Record length at line " + lineCount
                    );
                }

                // Checksum verification
                int sum = 0;
                for (byte b : bytes) {
                    sum += (b & 0xFF);
                }
                if ((sum & 0xFF) != 0xFF) {
                    throw new Stm8MappingException(
                        DiagnosticCode.STM8_FORMAT_UNSUPPORTED,
                        "Corrupted S-Record checksum on data record at line " + lineCount
                    );
                }

                int addrBytes = switch (typeChar) {
                    case '1', '9' -> 2;
                    case '2', '8' -> 3;
                    case '3', '7' -> 4;
                    default -> 0;
                };

                if (addrBytes == 0) {
                    continue; // S0 header or S5 count
                }

                long address = 0;
                for (int i = 0; i < addrBytes; i++) {
                    address = (address << 8) | (bytes[1 + i] & 0xFF);
                }

                int dataLen = count - addrBytes - 1;
                if (typeChar == '1' || typeChar == '2' || typeChar == '3') {
                    // Data record
                    for (int i = 0; i < dataLen; i++) {
                        long targetAddr = address + i;
                        byte b = bytes[1 + addrBytes + i];
                        if (targetAddr >= FLASH_BASE && targetAddr < FLASH_END) {
                            int slot = (int) (targetAddr - FLASH_BASE);
                            if (touched[slot] && memory[slot] != b) {
                                throw new Stm8MappingException(
                                    DiagnosticCode.STM8_FORMAT_UNSUPPORTED,
                                    String.format(
                                        "Overlapping S-Record conflict at 0x%06X (line %d)", targetAddr, lineCount)
                                );
                            }
                            memory[slot] = b;
                            touched[slot] = true;
                            if (targetAddr < minAddr) {
                                minAddr = targetAddr;
                            }
                            if (targetAddr + 1 > maxAddr) {
                                maxAddr = targetAddr + 1;
                            }
                        }
                    }
                } else if (typeChar == '7' || typeChar == '8' || typeChar == '9') {
                    // Termination record with entry point
                    entryPoint = address;
                }
            }
        } catch (IOException e) {
            throw new Stm8MappingException(
                DiagnosticCode.STM8_FORMAT_UNSUPPORTED, "Failed to read S-Record: " + e.getMessage(), e);
        }

        if (maxAddr <= FLASH_BASE) {
            throw new Stm8MappingException(
                DiagnosticCode.STM8_FORMAT_UNSUPPORTED,
                "S-Record contains no records in STM8 flash space [0x008000, 0x028000)"
            );
        }

        int flashSize = (int) (maxAddr - FLASH_BASE);
        byte[] flashBytes = Arrays.copyOf(memory, flashSize);
        if (entryPoint == 0 && flashSize >= 4 && (flashBytes[0] & 0xFF) == 0x82) {
            entryPoint = ((flashBytes[1] & 0xFFL) << 16) | ((flashBytes[2] & 0xFFL) << 8) | (flashBytes[3] & 0xFFL);
        }
        return new DecodedFirmware("MOTOROLA_S_RECORD", flashBytes, entryPoint, minAddr, maxAddr);
    }

    private static byte[] parseHexRecord(String line, int lineNum) throws Stm8MappingException {
        byte[] bytes = parseHexBytes(line.substring(1));
        if (bytes.length < 5) {
            throw new Stm8MappingException(
                DiagnosticCode.STM8_FORMAT_UNSUPPORTED, "Hex line too short at line " + lineNum);
        }
        int sum = 0;
        for (byte b : bytes) {
            sum += (b & 0xFF);
        }
        if ((sum & 0xFF) != 0) {
            throw new Stm8MappingException(
                DiagnosticCode.STM8_FORMAT_UNSUPPORTED,
                "Corrupted record checksum on Intel HEX data record at line " + lineNum
            );
        }
        return bytes;
    }

    private static byte[] parseHexBytes(String hex) throws Stm8MappingException {
        if (hex.length() % 2 != 0) {
            throw new Stm8MappingException(DiagnosticCode.STM8_FORMAT_UNSUPPORTED, "Odd number of hex digits");
        }
        int len = hex.length() / 2;
        byte[] out = new byte[len];
        for (int i = 0; i < len; i++) {
            int high = Character.digit(hex.charAt(i * 2), 16);
            int low = Character.digit(hex.charAt(i * 2 + 1), 16);
            if (high == -1 || low == -1) {
                throw new Stm8MappingException(DiagnosticCode.STM8_FORMAT_UNSUPPORTED, "Invalid hex digit in record");
            }
            out[i] = (byte) ((high << 4) | low);
        }
        return out;
    }

    private static long read32(byte[] data, int offset, boolean bigEndian) {
        if (bigEndian) {
            return ((data[offset] & 0xFFL) << 24)
                | ((data[offset + 1] & 0xFFL) << 16)
                | ((data[offset + 2] & 0xFFL) << 8)
                | (data[offset + 3] & 0xFFL);
        } else {
            return (data[offset] & 0xFFL)
                | ((data[offset + 1] & 0xFFL) << 8)
                | ((data[offset + 2] & 0xFFL) << 16)
                | ((data[offset + 3] & 0xFFL) << 24);
        }
    }

    private static int read16(byte[] data, int offset, boolean bigEndian) {
        if (bigEndian) {
            return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
        } else {
            return (data[offset] & 0xFF) | ((data[offset + 1] & 0xFF) << 8);
        }
    }
}
