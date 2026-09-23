package io.github.rezabakhshi.embedra.analyzers.esp;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import java.util.Objects;
import java.util.zip.CRC32;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

/** Bounded, pure validation of a supplied PNG candidate; performs no carving. */
public final class PngCandidateClassifier {
    private static final byte[] SIGNATURE = {
        (byte) 0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a
    };

    private PngCandidateClassifier() {
    }

    public static PngCandidateStatus classify(byte[] input, ParserLimits limits,
            CancellationToken cancellation) throws DiagnosticException {
        Objects.requireNonNull(input, "input");
        Objects.requireNonNull(limits, "limits");
        Objects.requireNonNull(cancellation, "cancellation");
        cancellation.throwIfCancellationRequested();
        if (input.length < SIGNATURE.length
            || !Arrays.equals(SIGNATURE, Arrays.copyOf(input, SIGNATURE.length))) {
            return PngCandidateStatus.NOT_PNG;
        }
        if (input.length == SIGNATURE.length) {
            return PngCandidateStatus.SIGNATURE_COLLISION;
        }
        if (input.length > limits.maxInputBytes()
            || input.length > limits.maxAllocationBytes()) {
            return PngCandidateStatus.RESOURCE_LIMIT;
        }

        int position = SIGNATURE.length;
        int chunks = 0;
        int width = 0;
        int height = 0;
        int bytesPerPixel = 0;
        boolean sawIdat = false;
        boolean idatClosed = false;
        ByteArrayOutputStream imageData = new ByteArrayOutputStream();
        while (position < input.length) {
            cancellation.throwIfCancellationRequested();
            if (++chunks > limits.maxObjects()) {
                return PngCandidateStatus.RESOURCE_LIMIT;
            }
            if (input.length - position < 12) {
                return PngCandidateStatus.TRUNCATED;
            }
            long length = word(input, position);
            String type = new String(input, position + 4, 4,
                java.nio.charset.StandardCharsets.US_ASCII);
            if (chunks == 1 && (!type.equals("IHDR") || length != 13)) {
                return PngCandidateStatus.SIGNATURE_COLLISION;
            }
            if (!type.matches("[A-Za-z]{4}")) {
                return PngCandidateStatus.INVALID_HEADER;
            }
            if (length > Integer.MAX_VALUE || length > input.length - position - 12L) {
                return PngCandidateStatus.TRUNCATED;
            }
            int data = position + 8;
            int end = data + (int) length;
            if (type.equals("IHDR")) {
                if (chunks != 1) {
                    return PngCandidateStatus.INVALID_HEADER;
                }
                width = (int) word(input, data);
                height = (int) word(input, data + 4);
                int depth = input[data + 8] & 0xff;
                int color = input[data + 9] & 0xff;
                if (width <= 0 || height <= 0 || input[data + 10] != 0
                    || input[data + 11] != 0 || input[data + 12] != 0) {
                    return PngCandidateStatus.INVALID_HEADER;
                }
                if (depth != 8 || (color != 2 && color != 6)) {
                    return PngCandidateStatus.UNSUPPORTED;
                }
                bytesPerPixel = color == 2 ? 3 : 4;
                long inflated = (1L + (long) width * bytesPerPixel) * height;
                if (inflated > limits.maxAllocationBytes()
                    || inflated > Integer.MAX_VALUE) {
                    return PngCandidateStatus.RESOURCE_LIMIT;
                }
            }
            CRC32 crc = new CRC32();
            for (int cursor = position + 4; cursor < end; cursor += 4096) {
                cancellation.throwIfCancellationRequested();
                crc.update(input, cursor, Math.min(4096, end - cursor));
            }
            if (crc.getValue() != word(input, end)) {
                return PngCandidateStatus.INVALID_CRC;
            }
            if (type.equals("IDAT")) {
                if (idatClosed) {
                    return PngCandidateStatus.INVALID_HEADER;
                }
                if (imageData.size() + length > limits.maxAllocationBytes()) {
                    return PngCandidateStatus.RESOURCE_LIMIT;
                }
                imageData.write(input, data, (int) length);
                sawIdat = true;
            }
            else if (type.equals("IEND")) {
                if (length != 0 || !sawIdat || end + 4 != input.length) {
                    return PngCandidateStatus.INVALID_HEADER;
                }
                return inflate(imageData.toByteArray(), width, height,
                    bytesPerPixel, cancellation);
            }
            else if (!type.equals("IHDR") && Character.isUpperCase(type.charAt(0))) {
                return PngCandidateStatus.UNSUPPORTED;
            }
            if (sawIdat && !type.equals("IDAT")) {
                idatClosed = true;
            }
            position = end + 4;
        }
        return PngCandidateStatus.TRUNCATED;
    }

    private static PngCandidateStatus inflate(byte[] compressed, int width, int height,
            int bytesPerPixel, CancellationToken cancellation)
            throws DiagnosticException {
        int row = 1 + width * bytesPerPixel;
        byte[] decoded = new byte[row * height];
        Inflater inflater = new Inflater();
        try {
            inflater.setInput(compressed);
            int written = 0;
            while (written < decoded.length) {
                cancellation.throwIfCancellationRequested();
                int count = inflater.inflate(decoded, written,
                    Math.min(4096, decoded.length - written));
                if (count == 0) {
                    return PngCandidateStatus.INVALID_HEADER;
                }
                written += count;
            }
            if (!inflater.finished() || inflater.getRemaining() != 0) {
                return PngCandidateStatus.INVALID_HEADER;
            }
            for (int index = 0; index < decoded.length; index += row) {
                cancellation.throwIfCancellationRequested();
                if ((decoded[index] & 0xff) > 4) {
                    return PngCandidateStatus.INVALID_HEADER;
                }
            }
            return PngCandidateStatus.VALID;
        }
        catch (DataFormatException exception) {
            return PngCandidateStatus.INVALID_HEADER;
        }
        finally {
            inflater.end();
        }
    }

    private static long word(byte[] input, int offset) {
        return ((long) (input[offset] & 0xff) << 24)
            | ((long) (input[offset + 1] & 0xff) << 16)
            | ((long) (input[offset + 2] & 0xff) << 8)
            | (input[offset + 3] & 0xff);
    }
}
