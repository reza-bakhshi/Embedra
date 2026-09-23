package io.github.rezabakhshi.embedra.formats.esp;

import io.github.rezabakhshi.embedra.core.io.SourceRange;
import java.util.Objects;

/** Exact opaque payload of a non-executable or encrypted ESP partition. */
public record EspExtractedPartition(
        EspPartitionEntry entry,
        EspPartitionPayloadKind kind,
        SourceRange sourceRange,
        byte[] payload) {
    public EspExtractedPartition {
        Objects.requireNonNull(entry, "entry");
        Objects.requireNonNull(kind, "kind");
        Objects.requireNonNull(sourceRange, "sourceRange");
        payload = Objects.requireNonNull(payload, "payload").clone();
        if (entry.flashRange().offset() != sourceRange.offset()
            || entry.flashRange().length() != sourceRange.length()
            || sourceRange.length() != payload.length
            || entry.encrypted() != (kind == EspPartitionPayloadKind.ENCRYPTED_OPAQUE)
            || (kind == EspPartitionPayloadKind.ERASED_APPLICATION_SLOT
                && entry.type() != 0)) {
            throw new IllegalArgumentException("Invalid extracted ESP partition");
        }
    }

    @Override
    public byte[] payload() {
        return payload.clone();
    }
}
