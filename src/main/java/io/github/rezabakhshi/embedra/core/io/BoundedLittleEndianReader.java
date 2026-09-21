package io.github.rezabakhshi.embedra.core.io;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.util.Arrays;
import java.util.Objects;

/** Cursor-based little-endian reads confined to an explicit source range. */
public final class BoundedLittleEndianReader {
    private final byte[] input;

    private final SourceRange range;

    private final ParserLimits limits;

    private final CancellationToken cancellationToken;

    private long position;

    public BoundedLittleEndianReader(
            byte[] input,
            SourceRange range,
            ParserLimits limits,
            CancellationToken cancellationToken) {
        this.input = Objects.requireNonNull(input, "input");
        this.range = Objects.requireNonNull(range, "range");
        this.limits = Objects.requireNonNull(limits, "limits");
        this.cancellationToken = Objects.requireNonNull(cancellationToken, "cancellationToken");
        if (input.length > limits.maxInputBytes()) {
            throw new IllegalArgumentException("Input exceeds the configured input-byte limit");
        }
        if (range.endExclusive() > input.length) {
            throw new IllegalArgumentException("Source range exceeds the input length");
        }
        position = range.offset();
    }

    public long sourcePosition() {
        return position;
    }

    public long remaining() {
        return range.endExclusive() - position;
    }

    public int readUnsignedByte() throws DiagnosticException {
        ensureReadable(1, false);
        return input[(int) position++] & 0xff;
    }

    public int readUnsignedShort() throws DiagnosticException {
        ensureReadable(2, false);
        int index = (int) position;
        int value = (input[index] & 0xff) | ((input[index + 1] & 0xff) << 8);
        position += 2;
        return value;
    }

    public long readUnsignedInt() throws DiagnosticException {
        ensureReadable(4, false);
        int index = (int) position;
        long value = (input[index] & 0xffL)
            | ((input[index + 1] & 0xffL) << 8)
            | ((input[index + 2] & 0xffL) << 16)
            | ((input[index + 3] & 0xffL) << 24);
        position += 4;
        return value;
    }

    public long readLong() throws DiagnosticException {
        ensureReadable(8, false);
        int index = (int) position;
        long value = 0;
        for (int shift = 0; shift < Long.SIZE; shift += Byte.SIZE) {
            value |= (input[index++] & 0xffL) << shift;
        }
        position += 8;
        return value;
    }

    public byte[] readBytes(int length) throws DiagnosticException {
        ensureReadable(length, true);
        int start = (int) position;
        position += length;
        return Arrays.copyOfRange(input, start, start + length);
    }

    public void skip(long length) throws DiagnosticException {
        if (length < 0) {
            throw new IllegalArgumentException("Skip length must be non-negative");
        }
        ensureReadable(length, false);
        position += length;
    }

    private void ensureReadable(long length, boolean allocation) throws DiagnosticException {
        if (length < 0) {
            throw new IllegalArgumentException("Read length must be non-negative");
        }
        cancellationToken.throwIfCancellationRequested();
        if (allocation && length > limits.maxAllocationBytes()) {
            throw failure(DiagnosticCode.LIMIT_EXCEEDED,
                "Requested allocation exceeds the configured byte limit");
        }
        if (length > remaining()) {
            throw failure(DiagnosticCode.READ_OUT_OF_BOUNDS,
                "Read exceeds the bounded source range");
        }
    }

    private DiagnosticException failure(DiagnosticCode code, String message) {
        return new DiagnosticException(Diagnostic.error(code, message, new SourceRange(position, 0)));
    }
}
