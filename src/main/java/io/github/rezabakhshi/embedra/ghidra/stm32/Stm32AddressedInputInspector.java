package io.github.rezabakhshi.embedra.ghidra.stm32;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.elf.ElfException;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.app.util.bin.format.elf.ElfProgramHeader;
import ghidra.app.util.bin.format.elf.ElfProgramHeaderConstants;
import ghidra.app.util.bin.format.elf.ElfSectionHeader;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.app.util.opinion.IntelHexLoader;
import ghidra.app.util.opinion.IntelHexRecord;
import ghidra.app.util.opinion.IntelHexRecordReader;
import ghidra.app.util.opinion.Loader;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.core.stm32.input.Stm32AddressedInput;
import io.github.rezabakhshi.embedra.core.stm32.input.Stm32ElfInput;
import io.github.rezabakhshi.embedra.core.stm32.input.Stm32IntelHexInput;
import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.OptionalLong;

/** Extracts address facts with Ghidra's native readers; native loaders import the image. */
public final class Stm32AddressedInputInspector {
    private static final long ADDRESS_SPACE_END = 0x1_0000_0000L;

    private static final int MAX_HEX_LINE_BYTES = 1024;

    private Stm32AddressedInputInspector() {
    }

    public static Stm32AddressedInput inspect(ByteProvider provider, ParserLimits limits,
            CancellationToken cancellation) throws IOException, DiagnosticException {
        Objects.requireNonNull(provider, "provider");
        Objects.requireNonNull(limits, "limits");
        Objects.requireNonNull(cancellation, "cancellation");
        cancellation.throwIfCancellationRequested();
        long length = provider.length();
        if (length <= 0 || length > limits.maxInputBytes()) {
            throw new IOException("STM32 addressed input length is outside parser limits");
        }
        if (length >= 4 && provider.readByte(0) == 0x7f
            && provider.readByte(1) == 'E' && provider.readByte(2) == 'L'
            && provider.readByte(3) == 'F') {
            return inspectElf(provider, limits, cancellation);
        }
        if (provider.readByte(0) == ':') {
            return inspectHex(provider, limits, cancellation);
        }
        throw new IOException("Input is neither ELF/AXF nor Intel HEX");
    }

    public static Class<? extends Loader> nativeLoaderClass(Stm32AddressedInput input) {
        Objects.requireNonNull(input, "input");
        return switch (input.format()) {
            case ELF -> ElfLoader.class;
            case INTEL_HEX -> IntelHexLoader.class;
        };
    }

    private static Stm32ElfInput inspectElf(ByteProvider provider, ParserLimits limits,
            CancellationToken cancellation) throws IOException, DiagnosticException {
        final ElfHeader header;
        try {
            header = new ElfHeader(provider, message -> { });
            header.parse();
        } catch (ElfException | IllegalArgumentException exception) {
            throw new IOException("Invalid ELF/AXF header", exception);
        }
        cancellation.throwIfCancellationRequested();
        if (!header.is32Bit() || !header.isLittleEndian() || header.e_machine() != 40
            || !header.isExecutable()) {
            throw new IOException("ELF/AXF is not a 32-bit little-endian ARM executable");
        }
        ElfProgramHeader[] programHeaders = header.getProgramHeaders();
        ElfSectionHeader[] sectionHeaders = header.getSections();
        if (programHeaders == null || sectionHeaders == null
            || (long) programHeaders.length + sectionHeaders.length > limits.maxObjects()) {
            throw new IOException("ELF/AXF header count exceeds parser limits");
        }
        List<Stm32ElfInput.LoadSegment> segments = new ArrayList<>();
        for (ElfProgramHeader segment : programHeaders) {
            cancellation.throwIfCancellationRequested();
            if (segment.getType() != ElfProgramHeaderConstants.PT_LOAD) {
                continue;
            }
            checkSource(segment.getOffset(), segment.getFileSize(), provider.length());
            segments.add(new Stm32ElfInput.LoadSegment(segment.getVirtualAddress(),
                segment.getPhysicalAddress(), segment.getMemorySize(), segment.getOffset(),
                segment.getFileSize(), segment.getFlags()));
        }
        if (segments.isEmpty()) {
            throw new IOException("ELF/AXF contains no address-bearing load segment");
        }
        List<Stm32ElfInput.Section> sections = new ArrayList<>();
        for (ElfSectionHeader section : sectionHeaders) {
            cancellation.throwIfCancellationRequested();
            if (section.getType() != 8) { // SHT_NOBITS has no file bytes.
                checkSource(section.getOffset(), section.getSize(), provider.length());
            }
            sections.add(new Stm32ElfInput.Section(
                Objects.toString(section.getNameAsString(), ""), section.getAddress(),
                section.getSize(), section.getOffset(), section.getFlags(), section.getType()));
        }
        try {
            return new Stm32ElfInput(header.e_entry(), segments, sections);
        } catch (IllegalArgumentException exception) {
            throw new IOException("Invalid ELF/AXF encoded address", exception);
        }
    }

    private static Stm32IntelHexInput inspectHex(ByteProvider provider, ParserLimits limits,
            CancellationToken cancellation) throws IOException, DiagnosticException {
        HexState state = new HexState();
        try (InputStream input = new BufferedInputStream(provider.getInputStream(0))) {
            ByteArrayOutputStream line = new ByteArrayOutputStream();
            long position = 0;
            long lineStart = 0;
            int value;
            while ((value = input.read()) != -1) {
                if (++position > limits.maxInputBytes()) {
                    throw new IOException("Intel HEX exceeds input-byte limit");
                }
                if (value == '\n') {
                    state.accept(line.toByteArray(), lineStart, limits, cancellation);
                    line.reset();
                    lineStart = position;
                } else {
                    if (line.size() >= MAX_HEX_LINE_BYTES) {
                        throw new IOException("Intel HEX record line is too long");
                    }
                    line.write(value);
                }
            }
            if (line.size() != 0) {
                state.accept(line.toByteArray(), lineStart, limits, cancellation);
            }
        }
        if (!state.eof || state.records.isEmpty()) {
            throw new IOException("Intel HEX lacks data or an end-of-file record");
        }
        return new Stm32IntelHexInput(state.entry, state.records);
    }

    private static void checkSource(long offset, long size, long inputLength) throws IOException {
        if (offset < 0 || size < 0 || offset > inputLength || size > inputLength - offset) {
            throw new IOException("ELF/AXF source range exceeds the input");
        }
    }

    private static final class HexState {
        private final List<Stm32IntelHexInput.DataRecord> records = new ArrayList<>();

        private long base;

        private OptionalLong entry = OptionalLong.empty();

        private boolean eof;

        private int lineNumber;

        private void accept(byte[] bytes, long offset, ParserLimits limits,
                CancellationToken cancellation) throws IOException, DiagnosticException {
            cancellation.throwIfCancellationRequested();
            lineNumber++;
            int size = bytes.length;
            if (size > 0 && bytes[size - 1] == '\r') {
                size--;
            }
            if (size == 0) {
                return;
            }
            if (eof || lineNumber > limits.maxObjects()) {
                throw new IOException("Intel HEX has trailing records or exceeds object limit");
            }
            for (int index = 0; index < size; index++) {
                if ((bytes[index] & 0x80) != 0) {
                    throw new IOException("Intel HEX contains a non-ASCII byte");
                }
            }
            final IntelHexRecord record;
            try {
                record = IntelHexRecordReader.readRecord(
                    new String(bytes, 0, size, StandardCharsets.US_ASCII));
            } catch (IllegalArgumentException exception) {
                throw new IOException("Invalid Intel HEX record at line " + lineNumber, exception);
            }
            if (!record.isReportedChecksumCorrect()
                || record.getRecordLength() != record.getData().length) {
                throw new IOException("Intel HEX checksum or length mismatch at line " + lineNumber);
            }
            int loadOffset = record.getLoadOffset();
            byte[] data = record.getData();
            switch (record.getRecordType()) {
                case IntelHexRecord.DATA_RECORD_TYPE -> addData(base + loadOffset,
                    data.length, offset);
                case IntelHexRecord.END_OF_FILE_RECORD_TYPE -> {
                    requireShape(loadOffset, data, 0);
                    eof = true;
                }
                case IntelHexRecord.EXTENDED_SEGMENT_ADDRESS_RECORD_TYPE -> {
                    requireShape(loadOffset, data, 2);
                    base = unsigned16(data) << 4;
                }
                case IntelHexRecord.EXTENDED_LINEAR_ADDRESS_RECORD_TYPE -> {
                    requireShape(loadOffset, data, 2);
                    base = unsigned16(data) << 16;
                }
                case IntelHexRecord.START_SEGMENT_ADDRESS_RECORD -> {
                    requireShape(loadOffset, data, 4);
                    setEntry((((data[0] & 0xffL) << 8) | (data[1] & 0xffL)) * 16
                        + (((data[2] & 0xffL) << 8) | (data[3] & 0xffL)));
                }
                case IntelHexRecord.START_LINEAR_ADDRESS_RECORD_TYPE -> {
                    requireShape(loadOffset, data, 4);
                    setEntry(((data[0] & 0xffL) << 24) | ((data[1] & 0xffL) << 16)
                        | ((data[2] & 0xffL) << 8) | (data[3] & 0xffL));
                }
                default -> throw new IOException("Unsupported Intel HEX record type");
            }
        }

        private void addData(long address, int length, long offset) throws IOException {
            if (address < 0 || address >= ADDRESS_SPACE_END
                || length > ADDRESS_SPACE_END - address) {
                throw new IOException("Intel HEX data address overflows 32 bits");
            }
            if (length > 0) {
                records.add(new Stm32IntelHexInput.DataRecord(
                    address, length, offset, lineNumber));
            }
        }

        private void setEntry(long address) throws IOException {
            if (address < 0 || address >= ADDRESS_SPACE_END
                || entry.isPresent() && entry.getAsLong() != address) {
                throw new IOException("Conflicting Intel HEX start addresses");
            }
            entry = OptionalLong.of(address);
        }

        private static void requireShape(int offset, byte[] data, int expected)
                throws IOException {
            if (offset != 0 || data.length != expected) {
                throw new IOException("Invalid Intel HEX control-record shape");
            }
        }

        private static long unsigned16(byte[] data) {
            return ((data[0] & 0xffL) << 8) | (data[1] & 0xffL);
        }
    }
}
