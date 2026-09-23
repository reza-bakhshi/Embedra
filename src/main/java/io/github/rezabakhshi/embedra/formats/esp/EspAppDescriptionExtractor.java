package io.github.rezabakhshi.embedra.formats.esp;

import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticSeverity;
import io.github.rezabakhshi.embedra.core.io.SourceRange;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/** Bounded, non-fatal extraction of optional {@code esp_app_desc_t} metadata. */
public final class EspAppDescriptionExtractor {
    public static final long MAGIC = 0xabcd5432L;

    public static final int DESCRIPTOR_SIZE = 256;

    private EspAppDescriptionExtractor() {
    }

    public static EspAppDescriptionResult extract(EspImage image) {
        Objects.requireNonNull(image, "image");
        Diagnostic firstFailure = null;
        for (EspImageSegment segment : image.segments()) {
            byte[] data = segment.data();
            for (int offset = 0; offset <= data.length - Integer.BYTES; offset++) {
                if (unsignedInt(data, offset) != MAGIC) {
                    continue;
                }
                int available = data.length - offset;
                SourceRange candidateRange = new SourceRange(
                    segment.dataSourceRange().offset() + offset,
                    Math.min(available, DESCRIPTOR_SIZE));
                if (available < DESCRIPTOR_SIZE) {
                    if (firstFailure == null) {
                        firstFailure = warning(DiagnosticCode.ESP_APP_DESC_TRUNCATED,
                            "ESP application description is truncated", candidateRange);
                    }
                    continue;
                }
                try {
                    EspAppDescription description = decode(data, offset,
                        segment.loadAddress() + offset,
                        new SourceRange(candidateRange.offset(), DESCRIPTOR_SIZE));
                    return new EspAppDescriptionResult(Optional.of(description), List.of());
                }
                catch (IllegalArgumentException failure) {
                    if (firstFailure == null) {
                        firstFailure = warning(DiagnosticCode.ESP_APP_DESC_INVALID,
                            "ESP application description is invalid: " + failure.getMessage(),
                            new SourceRange(candidateRange.offset(), DESCRIPTOR_SIZE));
                    }
                }
            }
        }
        return new EspAppDescriptionResult(Optional.empty(),
            firstFailure == null ? List.of() : List.of(firstFailure));
    }

    private static EspAppDescription decode(byte[] data, int offset, long targetAddress,
            SourceRange sourceRange) {
        int pageSizeLog2 = Byte.toUnsignedInt(data[offset + 180]);
        if (pageSizeLog2 >= Long.SIZE - 1) {
            throw new IllegalArgumentException("MMU page-size exponent is out of range");
        }
        return new EspAppDescription(
            unsignedInt(data, offset),
            unsignedInt(data, offset + 4),
            boundedText(data, offset + 16, 32, "version"),
            boundedText(data, offset + 48, 32, "project name"),
            boundedText(data, offset + 80, 16, "build time"),
            boundedText(data, offset + 96, 16, "build date"),
            boundedText(data, offset + 112, 32, "IDF version"),
            Arrays.copyOfRange(data, offset + 144, offset + 176),
            unsignedShort(data, offset + 176),
            unsignedShort(data, offset + 178),
            1L << pageSizeLog2,
            targetAddress,
            sourceRange);
    }

    private static String boundedText(byte[] data, int offset, int width, String field) {
        int length = 0;
        while (length < width && data[offset + length] != 0) {
            length++;
        }
        try {
            String value = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(data, offset, length))
                .toString();
            if (value.codePoints().anyMatch(Character::isISOControl)) {
                throw new IllegalArgumentException(field + " contains control characters");
            }
            return value;
        }
        catch (CharacterCodingException failure) {
            throw new IllegalArgumentException(field + " is not valid UTF-8", failure);
        }
    }

    private static int unsignedShort(byte[] data, int offset) {
        return Byte.toUnsignedInt(data[offset]) | Byte.toUnsignedInt(data[offset + 1]) << 8;
    }

    private static long unsignedInt(byte[] data, int offset) {
        return Integer.toUnsignedLong(Byte.toUnsignedInt(data[offset])
            | Byte.toUnsignedInt(data[offset + 1]) << 8
            | Byte.toUnsignedInt(data[offset + 2]) << 16
            | Byte.toUnsignedInt(data[offset + 3]) << 24);
    }

    private static Diagnostic warning(DiagnosticCode code, String message,
            SourceRange sourceRange) {
        return new Diagnostic(code, DiagnosticSeverity.WARNING, message,
            Optional.of(sourceRange));
    }
}
