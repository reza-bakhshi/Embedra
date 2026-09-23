package io.github.rezabakhshi.embedra.formats.esp;

/** Evidence for how a validated partition-table flash offset was selected. */
public enum EspPartitionDiscoveryMethod {
    DEFAULT_OFFSET,
    BOUNDED_SCAN,
    EXPLICIT_OFFSET
}
