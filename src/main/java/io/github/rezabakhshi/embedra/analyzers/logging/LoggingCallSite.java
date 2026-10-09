package io.github.rezabakhshi.embedra.analyzers.logging;

import java.util.Collections;
import java.util.Map;
import java.util.Objects;

/**
 * Immutable record representing a recovered logging, assert, or panic call site (AN-004).
 *
 * @param callInstructionAddress address of the call instruction
 * @param targetFunctionAddress address of the invoked diagnostic/logging function
 * @param targetSymbol resolved symbol name (or blank if unmapped)
 * @param level classified diagnostic log level
 * @param formatString parsed format string descriptor
 * @param argumentReferences resolved call arguments (e.g. file, line, expression, message, tag)
 * @param confidence classification confidence (e.g. CONFIRMED, LIKELY, PLAUSIBLE)
 * @param explanation human-readable explanation of why and how this call was identified
 */
public record LoggingCallSite(
        long callInstructionAddress,
        long targetFunctionAddress,
        String targetSymbol,
        DiagnosticLogLevel level,
        FormatStringDescriptor formatString,
        Map<String, String> argumentReferences,
        String confidence,
        String explanation) {

    public LoggingCallSite {
        if (callInstructionAddress < 0) {
            throw new IllegalArgumentException("callInstructionAddress must not be negative");
        }
        targetSymbol = targetSymbol == null ? "" : targetSymbol;
        Objects.requireNonNull(level, "level must not be null");
        Objects.requireNonNull(formatString, "formatString must not be null");
        argumentReferences = argumentReferences == null ? Map.of() : Collections.unmodifiableMap(argumentReferences);
        confidence = confidence == null ? "LIKELY" : confidence;
        explanation = explanation == null ? "" : explanation;
    }

    public String fileName() {
        return argumentReferences.get("file");
    }

    public String lineNumber() {
        return argumentReferences.get("line");
    }

    public String expression() {
        return argumentReferences.get("expression");
    }

    public String message() {
        return argumentReferences.get("message");
    }

    public String tag() {
        return argumentReferences.get("tag");
    }

    /**
     * Generates a concise single-line summary of this logging or assert call site.
     */
    public String summary() {
        StringBuilder sb = new StringBuilder();
        sb.append("[").append(level.name()).append("] ");
        if (formatString != null && !formatString.rawText().isBlank()) {
            sb.append("\"").append(formatString.rawText()).append("\"");
        } else if (expression() != null) {
            sb.append("assert(").append(expression()).append(")");
        } else if (message() != null) {
            sb.append(message());
        } else if (!targetSymbol.isBlank()) {
            sb.append(targetSymbol);
        } else {
            sb.append("call @ 0x").append(Long.toHexString(targetFunctionAddress).toUpperCase());
        }

        if (fileName() != null) {
            sb.append(" (").append(fileName());
            if (lineNumber() != null) {
                sb.append(":").append(lineNumber());
            }
            sb.append(")");
        }
        return sb.toString();
    }
}
