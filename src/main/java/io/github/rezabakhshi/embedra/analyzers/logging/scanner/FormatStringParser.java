package io.github.rezabakhshi.embedra.analyzers.logging.scanner;

import io.github.rezabakhshi.embedra.analyzers.logging.FormatArgumentType;
import io.github.rezabakhshi.embedra.analyzers.logging.FormatSpecifier;
import io.github.rezabakhshi.embedra.analyzers.logging.FormatStringDescriptor;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses standard printf-style format strings, identifying specifiers, argument count, and types (AN-004).
 */
public final class FormatStringParser {

    /**
     * Regex matching printf format specifiers:
     * %[positional$][flags][width][.precision][length]type
     */
    private static final Pattern SPECIFIER_PATTERN = Pattern.compile(
            "%(?:(\\d+)\\$)?([-+#0 ]*)?(\\d+|\\*)?(?:\\.(\\d+|\\*))?(hh|h|ll|l|j|z|t|L)?([diuoxXfFeEgGaAcspn%])");

    public FormatStringParser() {
    }

    /**
     * Parses the given raw string as a printf format string.
     *
     * @param rawText candidate format string text
     * @param limits parser limits
     * @return parsed format string descriptor
     */
    public FormatStringDescriptor parse(String rawText, ParserLimits limits) {
        if (rawText == null || rawText.isEmpty()) {
            return FormatStringDescriptor.empty();
        }
        Objects.requireNonNull(limits, "limits must not be null");

        // Enforce maximum string inspection length
        int maxLen = (int) Math.min((long) rawText.length(), limits.maxInputBytes());
        String text = rawText.substring(0, maxLen);

        Matcher matcher = SPECIFIER_PATTERN.matcher(text);
        List<FormatSpecifier> specifiers = new ArrayList<>();
        List<FormatArgumentType> argumentTypes = new ArrayList<>();
        int specifierIndex = 0;
        int maxPositionalIndex = 0;
        boolean hasPositional = false;

        while (matcher.find()) {
            if (specifiers.size() >= limits.maxObjects()) {
                break;
            }

            String fullMatch = matcher.group(0);
            String posStr = matcher.group(1);
            String widthStr = matcher.group(3);
            String precStr = matcher.group(4);
            String typeChar = matcher.group(6);

            // Literal "%%" does not consume any arguments
            if ("%".equals(typeChar)) {
                continue;
            }

            boolean isPositional = posStr != null;
            int posIndex = -1;
            if (isPositional) {
                try {
                    posIndex = Integer.parseInt(posStr);
                    if (posIndex > maxPositionalIndex) {
                        maxPositionalIndex = posIndex;
                    }
                    hasPositional = true;
                } catch (NumberFormatException ignored) {
                    isPositional = false;
                }
            }

            // Handle variable width '*'
            int width = -1;
            if ("*".equals(widthStr)) {
                if (!hasPositional) {
                    argumentTypes.add(FormatArgumentType.INTEGER);
                }
            } else if (widthStr != null) {
                try {
                    width = Integer.parseInt(widthStr);
                } catch (NumberFormatException ignored) {
                    // default to -1
                }
            }

            // Handle variable precision '*'
            int precision = -1;
            if ("*".equals(precStr)) {
                if (!hasPositional) {
                    argumentTypes.add(FormatArgumentType.INTEGER);
                }
            } else if (precStr != null) {
                try {
                    precision = Integer.parseInt(precStr);
                } catch (NumberFormatException ignored) {
                    // default to -1
                }
            }

            FormatArgumentType argType = mapType(typeChar);
            if (!hasPositional) {
                argumentTypes.add(argType);
            }

            specifiers.add(new FormatSpecifier(
                    specifierIndex++,
                    fullMatch,
                    argType,
                    width,
                    precision,
                    isPositional,
                    posIndex));
        }

        int expectedArgs = hasPositional ? maxPositionalIndex : argumentTypes.size();

        return new FormatStringDescriptor(
                rawText,
                specifiers,
                expectedArgs,
                argumentTypes);
    }

    private static FormatArgumentType mapType(String typeChar) {
        if (typeChar == null || typeChar.isEmpty()) {
            return FormatArgumentType.UNKNOWN;
        }
        return switch (typeChar.charAt(0)) {
            case 's' -> FormatArgumentType.STRING;
            case 'd', 'i' -> FormatArgumentType.INTEGER;
            case 'u', 'o', 'x', 'X' -> FormatArgumentType.HEX_INTEGER;
            case 'p', 'n' -> FormatArgumentType.POINTER;
            case 'c' -> FormatArgumentType.CHARACTER;
            case 'f', 'F', 'e', 'E', 'g', 'G', 'a', 'A' -> FormatArgumentType.FLOAT;
            default -> FormatArgumentType.UNKNOWN;
        };
    }
}
