package io.github.rezabakhshi.embedra.formats.esp;

/** Conservative treatment of a non-executable partition payload before T021 handlers. */
public enum EspPartitionPayloadKind {
    DATA,
    CUSTOM,
    ENCRYPTED_OPAQUE,
    ERASED_APPLICATION_SLOT
}
