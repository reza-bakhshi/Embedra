package io.github.rezabakhshi.embedra.analyzers.diff;

import java.util.Objects;

/**
 * Change classification between baseline source and target firmware artifacts (T062).
 */
public enum DiffChangeKind {
    /**
     * Item exists in target but was absent in source.
     */
    ADDED("Added", true),

    /**
     * Item existed in source but is absent in target.
     */
    REMOVED("Removed", true),

    /**
     * Item exists in both with differing content, properties, or byte payload.
     */
    MODIFIED("Modified", true),

    /**
     * Item exists in both with identical content but at a different address or offset.
     */
    MOVED("Moved", true),

    /**
     * Item exists in both with identical content, address, and properties.
     */
    UNCHANGED("Unchanged", false);

    private final String displayName;

    private final boolean difference;

    DiffChangeKind(String displayName, boolean difference) {
        this.displayName = Objects.requireNonNull(displayName, "displayName");
        this.difference = difference;
    }

    public String displayName() {
        return displayName;
    }

    /**
     * Returns true if this kind represents an actual difference between source and target.
     */
    public boolean isDifference() {
        return difference;
    }
}
