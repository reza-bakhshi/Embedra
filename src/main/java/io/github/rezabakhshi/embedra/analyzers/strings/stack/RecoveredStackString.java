package io.github.rezabakhshi.embedra.analyzers.strings.stack;

import io.github.rezabakhshi.embedra.analyzers.strings.ExtractedString;
import io.github.rezabakhshi.embedra.analyzers.strings.StringConfidence;
import io.github.rezabakhshi.embedra.analyzers.strings.StringEncoding;
import io.github.rezabakhshi.embedra.analyzers.strings.StringProvenance;
import java.util.Objects;

/**
 * Immutable record representing a string recovered from immediate-to-stack store idioms.
 *
 * @param functionAddress entry address of the containing function
 * @param stackOffset relative stack offset where the string buffer was constructed
 * @param content decoded recovered string content
 * @param encoding character encoding of the string
 * @param confidence confidence assessment of the recovery
 * @param startInstructionAddress first instruction address involved in string construction
 * @param endInstructionAddress last instruction address involved in string construction
 * @param instructionCount number of distinct instructions contributing to the stack string
 */
public record RecoveredStackString(
        long functionAddress,
        long stackOffset,
        String content,
        StringEncoding encoding,
        StringConfidence confidence,
        long startInstructionAddress,
        long endInstructionAddress,
        int instructionCount) {

    public RecoveredStackString {
        if (functionAddress < 0) {
            throw new IllegalArgumentException("Function address must not be negative");
        }
        Objects.requireNonNull(content, "content must not be null");
        if (content.isEmpty()) {
            throw new IllegalArgumentException("Content must not be empty");
        }
        Objects.requireNonNull(encoding, "encoding must not be null");
        Objects.requireNonNull(confidence, "confidence must not be null");
        if (startInstructionAddress < 0 || endInstructionAddress < 0) {
            throw new IllegalArgumentException("Instruction addresses must not be negative");
        }
        if (instructionCount <= 0) {
            throw new IllegalArgumentException("Instruction count must be positive");
        }
    }

    /**
     * Converts this recovered stack string to an ExtractedString with STACK_CONSTRUCTED provenance.
     */
    public ExtractedString toExtractedString() {
        return new ExtractedString(
                startInstructionAddress,
                content.length(),
                encoding,
                content,
                confidence,
                StringProvenance.STACK_CONSTRUCTED,
                true);
    }

    /**
     * Returns a redacted string representation to avoid secret leaking in logs (AN-008).
     */
    public String redactedContent() {
        if (content.length() <= 8) {
            return content;
        }
        return content.substring(0, 3) + "..." + content.substring(content.length() - 2);
    }
}
