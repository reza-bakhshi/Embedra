package io.github.rezabakhshi.embedra.analyzers.strings;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;

/**
 * Pure multi-encoding string scanner over byte slices and memory blocks.
 *
 * <p>Supports ASCII, UTF-8, UTF-16LE, UTF-16BE, and Pascal length-prefixed formats
 * under strict bounds and cooperative cancellation.</p>
 */
public final class MultiEncodingStringScanner {

    public MultiEncodingStringScanner() {
    }

    /**
     * Scans byte data using default scan options and limits.
     */
    public List<ExtractedString> scan(byte[] data, long baseAddress) throws DiagnosticException {
        return scan(data, baseAddress, StringScanOptions.defaults(),
                ParserLimits.defaults(), CancellationToken.none());
    }

    /**
     * Scans byte data with explicit options, limits, and cooperative cancellation.
     */
    public List<ExtractedString> scan(
            byte[] data,
            long baseAddress,
            StringScanOptions options,
            ParserLimits limits,
            CancellationToken token) throws DiagnosticException {
        Objects.requireNonNull(data, "data must not be null");
        Objects.requireNonNull(options, "options must not be null");
        Objects.requireNonNull(limits, "limits must not be null");
        Objects.requireNonNull(token, "token must not be null");

        if (baseAddress < 0) {
            throw new IllegalArgumentException("Base address must not be negative");
        }
        if (data.length > limits.maxInputBytes() || data.length > limits.maxAllocationBytes()) {
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.LIMIT_EXCEEDED,
                    "Input byte length exceeds configured resource limits: " + data.length, null));
        }

        Instant startTime = Instant.now();
        List<ExtractedString> results = new ArrayList<>();
        long extractedBytes = 0;

        // 1. Scan ASCII and UTF-8
        if (options.scanAscii() || options.scanUtf8()) {
            extractedBytes = scanAsciiAndUtf8(data, baseAddress, options, limits,
                    token, startTime, results, extractedBytes);
        }

        // 2. Scan UTF-16LE and UTF-16BE
        if (options.scanUtf16Le() || options.scanUtf16Be()) {
            extractedBytes = scanUtf16(data, baseAddress, options, limits,
                    token, startTime, results, extractedBytes);
        }

        // 3. Scan Pascal (length-prefixed) strings
        if (options.scanPascal()) {
            extractedBytes = scanPascalStrings(data, baseAddress, options, limits,
                    token, startTime, results, extractedBytes);
        }

        results.sort(Comparator.comparingLong(ExtractedString::offset)
                .thenComparing(Comparator.comparingInt(ExtractedString::length).reversed()));

        return List.copyOf(results);
    }

    private long scanAsciiAndUtf8(
            byte[] data,
            long baseAddress,
            StringScanOptions options,
            ParserLimits limits,
            CancellationToken token,
            Instant startTime,
            List<ExtractedString> results,
            long currentExtractedBytes) throws DiagnosticException {
        long extractedBytes = currentExtractedBytes;
        int i = 0;

        while (i < data.length) {
            if ((i & 0x3FF) == 0) {
                checkLimitsAndCancellation(token, startTime, limits, results.size(), extractedBytes);
            }

            int start = i;
            StringBuilder sb = new StringBuilder();
            int printableCount = 0;
            boolean hasNonAscii = false;
            boolean nullTerminated = false;

            while (i < data.length) {
                int b = data[i] & 0xFF;
                if (b == 0x00) {
                    nullTerminated = true;
                    i++; // consume null terminator
                    break;
                }

                // Check 1-byte ASCII
                if (b < 0x80) {
                    if (isPrintableAscii(b)) {
                        sb.append((char) b);
                        printableCount++;
                        i++;
                    } else {
                        // Non-printable control char ends sequence
                        break;
                    }
                } else if (options.scanUtf8()) {
                    // Try parsing multi-byte UTF-8 sequence
                    int seqLen = getUtf8SequenceLength(b);
                    if (seqLen > 1 && i + seqLen <= data.length) {
                        int codePoint = decodeUtf8CodePoint(data, i, seqLen);
                        if (codePoint > 0 && isPrintableCodePoint(codePoint)) {
                            sb.append(Character.toChars(codePoint));
                            printableCount++;
                            hasNonAscii = true;
                            i += seqLen;
                        } else {
                            break;
                        }
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            }

            int charLength = sb.length();
            if (charLength >= options.minLength()) {
                double ratio = (double) printableCount / charLength;
                if (ratio >= options.minPrintableRatio()) {
                    StringEncoding encoding = hasNonAscii ? StringEncoding.UTF_8 : StringEncoding.ASCII;
                    boolean enabled = hasNonAscii ? options.scanUtf8() : options.scanAscii();
                    if (enabled) {
                        int byteLen = i - start;
                        StringConfidence confidence = determineConfidence(charLength, ratio, nullTerminated);
                        ExtractedString str = new ExtractedString(
                                baseAddress + start, byteLen, encoding, sb.toString(),
                                confidence, StringProvenance.STATIC_LITERAL, nullTerminated);
                        results.add(str);
                        extractedBytes += byteLen;
                        if (results.size() >= options.maxStrings() || results.size() >= limits.maxObjects()
                                || extractedBytes > limits.maxExtractedBytes()) {
                            return extractedBytes;
                        }
                    }
                }
            }

            if (i == start) {
                i++;
            }
        }

        return extractedBytes;
    }

    private long scanUtf16(
            byte[] data,
            long baseAddress,
            StringScanOptions options,
            ParserLimits limits,
            CancellationToken token,
            Instant startTime,
            List<ExtractedString> results,
            long currentExtractedBytes) throws DiagnosticException {
        long extractedBytes = currentExtractedBytes;
        if (options.scanUtf16Le()) {
            extractedBytes = scanUtf16Specific(data, baseAddress, options, limits,
                    token, startTime, results, extractedBytes, true);
        }
        if (options.scanUtf16Be()) {
            extractedBytes = scanUtf16Specific(data, baseAddress, options, limits,
                    token, startTime, results, extractedBytes, false);
        }
        return extractedBytes;
    }

    private long scanUtf16Specific(
            byte[] data,
            long baseAddress,
            StringScanOptions options,
            ParserLimits limits,
            CancellationToken token,
            Instant startTime,
            List<ExtractedString> results,
            long currentExtractedBytes,
            boolean isLe) throws DiagnosticException {
        long extractedBytes = currentExtractedBytes;

        for (int align = 0; align <= 1; align++) {
            int i = align;
            while (i + 1 < data.length) {
                if ((i & 0x3FF) == 0) {
                    checkLimitsAndCancellation(token, startTime, limits, results.size(), extractedBytes);
                }

                int start = i;
                StringBuilder sb = new StringBuilder();
                int zeroCount = 0;
                int count = 0;
                boolean nullTerminated = false;

                while (i + 1 < data.length) {
                    int b0 = data[i] & 0xFF;
                    int b1 = data[i + 1] & 0xFF;

                    int cu = isLe ? (b0 | (b1 << 8)) : ((b0 << 8) | b1);

                    if (cu == 0x0000) {
                        nullTerminated = true;
                        i += 2;
                        break;
                    }

                    boolean isAsciiMatch = isLe
                            ? (b1 == 0 && isPrintableAscii(b0))
                            : (b0 == 0 && isPrintableAscii(b1));
                    boolean isUnicodeMatch = isPrintableCodePoint(cu);

                    if (isAsciiMatch) {
                        zeroCount++;
                        sb.append((char) cu);
                        count++;
                        i += 2;
                    } else if (isUnicodeMatch && Character.isLetterOrDigit(cu)) {
                        sb.append((char) cu);
                        count++;
                        i += 2;
                    } else {
                        break;
                    }
                }

                if (count >= options.minLength()) {
                    double zeroRatio = (double) zeroCount / count;
                    if (zeroRatio >= 0.70) {
                        int byteLen = i - start;
                        String content = sb.toString();
                        StringConfidence confidence = determineConfidence(content.length(), 1.0, nullTerminated);
                        StringEncoding encoding = isLe ? StringEncoding.UTF_16LE : StringEncoding.UTF_16BE;
                        ExtractedString str = new ExtractedString(
                                baseAddress + start, byteLen, encoding, content,
                                confidence, StringProvenance.STATIC_LITERAL, nullTerminated);
                        results.add(str);
                        extractedBytes += byteLen;
                        if (results.size() >= options.maxStrings() || results.size() >= limits.maxObjects()
                                || extractedBytes > limits.maxExtractedBytes()) {
                            return extractedBytes;
                        }
                    }
                }

                if (i == start) {
                    i += 2;
                }
            }
        }

        return extractedBytes;
    }

    private long scanPascalStrings(
            byte[] data,
            long baseAddress,
            StringScanOptions options,
            ParserLimits limits,
            CancellationToken token,
            Instant startTime,
            List<ExtractedString> results,
            long currentExtractedBytes) throws DiagnosticException {
        long extractedBytes = currentExtractedBytes;
        int i = 0;

        while (i < data.length) {
            if ((i & 0x3FF) == 0) {
                checkLimitsAndCancellation(token, startTime, limits, results.size(), extractedBytes);
            }

            // Pascal 8-bit length
            int len8 = data[i] & 0xFF;
            if (len8 >= options.minLength() && len8 <= 255 && i + 1 + len8 <= data.length) {
                String candidate = tryExtractAscii(data, i + 1, len8, options.minPrintableRatio());
                if (candidate != null) {
                    StringConfidence confidence = candidate.length() >= 8
                            ? StringConfidence.CONFIRMED : StringConfidence.LIKELY;
                    ExtractedString str = new ExtractedString(
                            baseAddress + i, 1 + len8, StringEncoding.PASCAL_8, candidate,
                            confidence, StringProvenance.STATIC_LITERAL, false);
                    results.add(str);
                    extractedBytes += 1 + len8;
                    i += 1 + len8;
                    if (results.size() >= options.maxStrings() || results.size() >= limits.maxObjects()
                            || extractedBytes > limits.maxExtractedBytes()) {
                        return extractedBytes;
                    }
                    continue;
                }
            }

            // Pascal 16-bit length (little-endian)
            if (i + 2 <= data.length) {
                int len16 = (data[i] & 0xFF) | ((data[i + 1] & 0xFF) << 8);
                if (len16 >= options.minLength() && len16 <= 1024 && i + 2 + len16 <= data.length) {
                    String candidate = tryExtractAscii(data, i + 2, len16, options.minPrintableRatio());
                    if (candidate != null) {
                        StringConfidence confidence = candidate.length() >= 8
                                ? StringConfidence.CONFIRMED : StringConfidence.LIKELY;
                        ExtractedString str = new ExtractedString(
                                baseAddress + i, 2 + len16, StringEncoding.PASCAL_16, candidate,
                                confidence, StringProvenance.STATIC_LITERAL, false);
                        results.add(str);
                        extractedBytes += 2 + len16;
                        i += 2 + len16;
                        if (results.size() >= options.maxStrings() || results.size() >= limits.maxObjects()
                                || extractedBytes > limits.maxExtractedBytes()) {
                            return extractedBytes;
                        }
                        continue;
                    }
                }
            }

            i++;
        }

        return extractedBytes;
    }

    private static String tryExtractAscii(byte[] data, int start, int length, double minRatio) {
        StringBuilder sb = new StringBuilder(length);
        int printable = 0;
        for (int j = 0; j < length; j++) {
            int b = data[start + j] & 0xFF;
            if (isPrintableAscii(b)) {
                sb.append((char) b);
                printable++;
            } else {
                return null; // Pascal payload should be clean printable characters
            }
        }
        if ((double) printable / length >= minRatio) {
            return sb.toString();
        }
        return null;
    }

    private static boolean isPrintableAscii(int b) {
        return (b >= 0x20 && b <= 0x7E) || b == '\t' || b == '\r' || b == '\n';
    }

    private static boolean isPrintableCodePoint(int cp) {
        if ((cp >= 0x20 && cp <= 0x7E) || cp == '\t' || cp == '\r' || cp == '\n') {
            return true;
        }
        return !Character.isISOControl(cp) && Character.isDefined(cp);
    }

    private static int getUtf8SequenceLength(int firstByte) {
        if ((firstByte & 0xE0) == 0xC0) {
            return 2;
        }
        if ((firstByte & 0xF0) == 0xE0) {
            return 3;
        }
        if ((firstByte & 0xF8) == 0xF0) {
            return 4;
        }
        return 0;
    }

    private static int decodeUtf8CodePoint(byte[] data, int offset, int length) {
        int b0 = data[offset] & 0xFF;
        if (length == 2) {
            if (b0 < 0xC2 || b0 > 0xDF) {
                return -1; // Overlong
            }
            int b1 = data[offset + 1] & 0xFF;
            if ((b1 & 0xC0) != 0x80) {
                return -1;
            }
            return ((b0 & 0x1F) << 6) | (b1 & 0x3F);
        }
        if (length == 3) {
            int b1 = data[offset + 1] & 0xFF;
            int b2 = data[offset + 2] & 0xFF;
            if ((b1 & 0xC0) != 0x80 || (b2 & 0xC0) != 0x80) {
                return -1;
            }
            if (b0 == 0xE0 && b1 < 0xA0) {
                return -1; // Overlong
            }
            if (b0 == 0xED && b1 >= 0xA0) {
                return -1; // UTF-16 surrogate
            }
            return ((b0 & 0x0F) << 12) | ((b1 & 0x3F) << 6) | (b2 & 0x3F);
        }
        if (length == 4) {
            int b1 = data[offset + 1] & 0xFF;
            int b2 = data[offset + 2] & 0xFF;
            int b3 = data[offset + 3] & 0xFF;
            if ((b1 & 0xC0) != 0x80 || (b2 & 0xC0) != 0x80 || (b3 & 0xC0) != 0x80) {
                return -1;
            }
            if (b0 == 0xF0 && b1 < 0x90) {
                return -1; // Overlong
            }
            if (b0 == 0xF4 && b1 > 0x8F) {
                return -1; // Above 0x10FFFF
            }
            return ((b0 & 0x07) << 18) | ((b1 & 0x3F) << 12) | ((b2 & 0x3F) << 6) | (b3 & 0x3F);
        }
        return -1;
    }

    private static StringConfidence determineConfidence(int length, double ratio, boolean nullTerminated) {
        if (nullTerminated && ratio >= 0.99 && length >= 4) {
            return StringConfidence.CONFIRMED;
        }
        if (length >= 8 && ratio >= 0.95) {
            return StringConfidence.CONFIRMED;
        }
        if (length >= 4 && ratio >= 0.85) {
            return StringConfidence.LIKELY;
        }
        return StringConfidence.PLAUSIBLE;
    }

    private static void checkLimitsAndCancellation(
            CancellationToken token,
            Instant startTime,
            ParserLimits limits,
            int objects,
            long extractedBytes) throws DiagnosticException {
        token.throwIfCancellationRequested();
        if (Duration.between(startTime, Instant.now()).compareTo(limits.maxWallTime()) > 0
                || objects > limits.maxObjects()
                || extractedBytes > limits.maxExtractedBytes()) {
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.LIMIT_EXCEEDED,
                    "Multi-encoding string scanner exceeded configured resource limits", null));
        }
    }
}
