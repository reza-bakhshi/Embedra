package io.github.rezabakhshi.embedra.core.stm32.input;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.core.io.SourceRange;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.zip.CRC32;

/** Strict, bounded parser for the addressed ST DfuSe version 1 file container. */
public final class Stm32DfuParser {
    private static final int PREFIX_LENGTH = 11;

    private static final int TARGET_HEADER_LENGTH = 274;

    private static final int ELEMENT_HEADER_LENGTH = 8;

    private static final int SUFFIX_LENGTH = 16;

    private static final long ADDRESS_SPACE_END = 0x1_0000_0000L;

    private Stm32DfuParser() {
    }

    public static Stm32DfuImage parse(byte[] input, ParserLimits limits,
            CancellationToken cancellation) throws DiagnosticException {
        Objects.requireNonNull(input, "input");
        Objects.requireNonNull(limits, "limits");
        Objects.requireNonNull(cancellation, "cancellation");
        cancellation.throwIfCancellationRequested();
        if (input.length > limits.maxInputBytes()) {
            throw failure(DiagnosticCode.LIMIT_EXCEEDED, "DFU input exceeds the byte limit", 0);
        }
        if (input.length < PREFIX_LENGTH + TARGET_HEADER_LENGTH
                + ELEMENT_HEADER_LENGTH + 1 + SUFFIX_LENGTH) {
            throw invalid("DFU container is truncated", input.length);
        }
        long started = System.nanoTime();
        Cursor cursor = new Cursor(input);
        cursor.signature("DfuSe");
        if (cursor.u8() != 1 || cursor.u32() != input.length) {
            throw invalid("Unsupported DFU version or declared file size", cursor.position());
        }
        int targetCount = cursor.u8();
        if (targetCount == 0 || targetCount > limits.maxObjects()) {
            throw invalid("Invalid DFU target count", cursor.position());
        }
        int bodyEnd = input.length - SUFFIX_LENGTH;
        List<Stm32DfuImage.Target> targets = new ArrayList<>();
        boolean[] alternateSettings = new boolean[256];
        long objects = targetCount;
        long payloadBytes = 0;
        for (int targetIndex = 0; targetIndex < targetCount; targetIndex++) {
            checkpoint(cancellation, limits, started);
            cursor.require(TARGET_HEADER_LENGTH, bodyEnd);
            cursor.signature("Target");
            int alternateSetting = cursor.u8();
            if (alternateSettings[alternateSetting]) {
                throw invalid("Repeated DFU alternate setting", cursor.position());
            }
            alternateSettings[alternateSetting] = true;
            long named = cursor.u32();
            if (named > 1) {
                throw invalid("Invalid DFU target-name flag", cursor.position());
            }
            String name = cursor.name(named == 1);
            long targetSize = cursor.u32();
            long elementCount = cursor.u32();
            if (elementCount == 0) {
                throw invalid("DFU target has no elements", cursor.position());
            }
            if (elementCount > limits.maxObjects() - objects) {
                throw failure(DiagnosticCode.LIMIT_EXCEEDED,
                    "DFU element count exceeds the object limit", cursor.position());
            }
            objects += elementCount;
            int targetStart = cursor.position();
            if (targetSize > bodyEnd - targetStart
                    || elementCount > targetSize / ELEMENT_HEADER_LENGTH) {
                throw invalid("DFU target size cannot contain its elements", cursor.position());
            }
            long targetEnd = targetStart + targetSize;
            List<Stm32DfuImage.Element> elements = new ArrayList<>();
            for (long elementIndex = 0; elementIndex < elementCount; elementIndex++) {
                checkpoint(cancellation, limits, started);
                cursor.require(ELEMENT_HEADER_LENGTH, targetEnd);
                long address = cursor.u32();
                long size = cursor.u32();
                if (size == 0 || address >= ADDRESS_SPACE_END
                        || size > ADDRESS_SPACE_END - address) {
                    throw invalid("Invalid DFU element address or size", cursor.position());
                }
                if (size > targetEnd - cursor.position()) {
                    throw invalid("DFU element exceeds its target", cursor.position());
                }
                if (size > limits.maxExtractedBytes() - payloadBytes) {
                    throw failure(DiagnosticCode.LIMIT_EXCEEDED,
                        "DFU payload exceeds the extracted-byte limit", cursor.position());
                }
                payloadBytes += size;
                elements.add(new Stm32DfuImage.Element(address,
                    new SourceRange(cursor.position(), size)));
                cursor.skip(size);
            }
            if (cursor.position() != targetEnd) {
                throw invalid("DFU target length does not match its elements", cursor.position());
            }
            List<Stm32DfuImage.Element> ordered = new ArrayList<>(elements);
            ordered.sort(Comparator.comparingLong(Stm32DfuImage.Element::encodedAddress));
            for (int index = 1; index < ordered.size(); index++) {
                if (ordered.get(index - 1).endExclusive()
                        > ordered.get(index).encodedAddress()) {
                    throw invalid("Overlapping DFU elements", targetStart);
                }
            }
            targets.add(new Stm32DfuImage.Target(alternateSetting, name,
                new SourceRange(targetStart, targetSize), elements));
        }
        if (cursor.position() != bodyEnd) {
            throw invalid("DFU body length does not match target count", cursor.position());
        }
        int deviceVersion = cursor.u16();
        int productId = cursor.u16();
        int vendorId = cursor.u16();
        int dfuVersion = cursor.u16();
        cursor.signature("UFD");
        int suffixLength = cursor.u8();
        long storedCrc = cursor.u32();
        if (dfuVersion != 0x011a || suffixLength != SUFFIX_LENGTH) {
            throw invalid("Unsupported DFU suffix version or length", bodyEnd);
        }
        CRC32 crc = new CRC32();
        for (int offset = 0; offset < input.length - 4; offset += 4096) {
            checkpoint(cancellation, limits, started);
            crc.update(input, offset, Math.min(4096, input.length - 4 - offset));
        }
        if ((~crc.getValue() & 0xffff_ffffL) != storedCrc) {
            throw failure(DiagnosticCode.STM_DFU_CRC_MISMATCH,
                "DFU suffix CRC does not match the file", input.length - 4);
        }
        return new Stm32DfuImage(targets,
            new Stm32DfuImage.Suffix(deviceVersion, productId, vendorId,
                dfuVersion, storedCrc));
    }

    private static void checkpoint(CancellationToken cancellation, ParserLimits limits,
            long started) throws DiagnosticException {
        cancellation.throwIfCancellationRequested();
        if (System.nanoTime() - started > limits.maxWallTime().toNanos()) {
            throw failure(DiagnosticCode.LIMIT_EXCEEDED, "DFU parse time limit exceeded", 0);
        }
    }

    private static DiagnosticException invalid(String message, long offset) {
        return failure(DiagnosticCode.STM_DFU_INVALID, message, offset);
    }

    private static DiagnosticException failure(DiagnosticCode code, String message, long offset) {
        return new DiagnosticException(Diagnostic.error(code, message, new SourceRange(offset, 0)));
    }

    private static final class Cursor {
        private final byte[] input;

        private int position;

        private Cursor(byte[] input) {
            this.input = input;
        }

        private int position() {
            return position;
        }

        private void require(long size, long end) throws DiagnosticException {
            if (size < 0 || size > end - position) {
                throw invalid("DFU record is truncated", position);
            }
        }

        private int u8() {
            return input[position++] & 0xff;
        }

        private int u16() {
            return u8() | (u8() << 8);
        }

        private long u32() {
            return (u16() & 0xffffL) | ((u16() & 0xffffL) << 16);
        }

        private void signature(String expected) throws DiagnosticException {
            require(expected.length(), input.length);
            for (int index = 0; index < expected.length(); index++) {
                if (u8() != expected.charAt(index)) {
                    throw invalid("Unexpected DFU signature", position - 1);
                }
            }
        }

        private String name(boolean named) {
            int start = position;
            position += 255;
            if (!named) {
                return "";
            }
            int end = start;
            while (end < position && input[end] != 0) {
                end++;
            }
            return new String(input, start, end - start, StandardCharsets.ISO_8859_1);
        }

        private void skip(long size) {
            position += (int) size;
        }
    }
}
