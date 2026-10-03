package io.github.rezabakhshi.embedra.analyzers.strings;

import java.util.Objects;

/**
 * Immutable record representing a string extracted from binary data or reconstructed from stack instructions.
 *
 * @param offset memory address or buffer offset where the string begins
 * @param length byte length of the encoded string in memory
 * @param encoding detected character encoding format
 * @param content decoded string content
 * @param confidence confidence assessment of the detection
 * @param provenance origin of the string (static literal vs stack-constructed)
 * @param nullTerminated true if the string ends with a null terminator in memory
 */
public record ExtractedString(
        long offset,
        int length,
        StringEncoding encoding,
        String content,
        StringConfidence confidence,
        StringProvenance provenance,
        boolean nullTerminated) {

    public ExtractedString {
        if (offset < 0) {
            throw new IllegalArgumentException("Offset must be non-negative: " + offset);
        }
        if (length <= 0) {
            throw new IllegalArgumentException("Length must be positive: " + length);
        }
        Objects.requireNonNull(encoding, "encoding must not be null");
        Objects.requireNonNull(content, "content must not be null");
        if (content.isEmpty()) {
            throw new IllegalArgumentException("Content must not be empty");
        }
        Objects.requireNonNull(confidence, "confidence must not be null");
        Objects.requireNonNull(provenance, "provenance must not be null");
    }

    /**
     * Convenience constructor defaulting nullTerminated to false.
     */
    public ExtractedString(
            long offset,
            int length,
            StringEncoding encoding,
            String content,
            StringConfidence confidence,
            StringProvenance provenance) {
        this(offset, length, encoding, content, confidence, provenance, false);
    }

    /**
     * Returns a redacted string representation to prevent secret leaking in logs (AN-008).
     */
    public String redactedContent() {
        if (content.length() <= 8) {
            return content;
        }
        return content.substring(0, 3) + "..." + content.substring(content.length() - 2);
    }
}
