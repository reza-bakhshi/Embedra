package io.github.rezabakhshi.embedra.targets;

/** Target-independent memory-region categories used by provider decisions. */
public enum MemoryRegionKind {
    DROM,
    IROM,
    DRAM,
    IRAM,
    RTC_DATA,
    UNKNOWN
}
