package io.github.rezabakhshi.embedra.formats.esp;

/** Safe result of inspecting a partition without mounting or executing it. */
public enum EspPartitionDisposition {
    ERASED,
    VALIDATED_METADATA,
    OPAQUE,
    CONFIGURATION_REQUIRED,
    SENSITIVE_REDACTED,
    INVALID
}
