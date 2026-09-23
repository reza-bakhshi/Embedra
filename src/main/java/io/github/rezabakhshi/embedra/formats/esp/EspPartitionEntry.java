package io.github.rezabakhshi.embedra.formats.esp;

import io.github.rezabakhshi.embedra.core.io.SourceRange;
import java.util.Objects;

/** Immutable validated ESP partition entry with an exact physical flash range. */
public record EspPartitionEntry(
        int index,
        String label,
        int type,
        int subtype,
        EspFlashRange flashRange,
        long flags,
        SourceRange sourceRange) {
    private static final long ENCRYPTED_FLAG = 1;

    private static final long READ_ONLY_FLAG = 2;

    public EspPartitionEntry {
        Objects.requireNonNull(label, "label");
        Objects.requireNonNull(flashRange, "flashRange");
        Objects.requireNonNull(sourceRange, "sourceRange");
        if (index < 0 || label.isBlank() || type < 0 || type > 0xff
            || subtype < 0 || subtype > 0xff || flashRange.length() == 0
            || flags < 0 || flags > 0xffff_ffffL || sourceRange.length() != 32) {
            throw new IllegalArgumentException("Invalid ESP partition entry model");
        }
    }

    public boolean encrypted() {
        return (flags & ENCRYPTED_FLAG) != 0;
    }

    public boolean readOnly() {
        return (flags & READ_ONLY_FLAG) != 0;
    }
}
