package io.github.rezabakhshi.embedra.analyzers.esp;

/** Exact content/location relationship between two firmware artifacts. */
public enum EspArtifactChangeKind {
    UNCHANGED,
    MOVED,
    MODIFIED,
    ADDED,
    REMOVED
}
