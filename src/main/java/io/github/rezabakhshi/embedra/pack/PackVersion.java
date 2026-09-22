package io.github.rezabakhshi.embedra.pack;

import java.util.Objects;

/** Strict numeric pack version used for deterministic offline selection. */
public record PackVersion(int major, int minor, int patch) implements Comparable<PackVersion> {
    public PackVersion {
        if (major < 0 || minor < 0 || patch < 0) {
            throw new IllegalArgumentException("Pack version components must be non-negative");
        }
    }

    public static PackVersion parse(String value) {
        Objects.requireNonNull(value, "value");
        if (!value.matches("(?:0|[1-9][0-9]*)\\.(?:0|[1-9][0-9]*)\\.(?:0|[1-9][0-9]*)")) {
            throw new IllegalArgumentException("Pack version must use MAJOR.MINOR.PATCH");
        }
        String[] components = value.split("\\.");
        try {
            return new PackVersion(Integer.parseInt(components[0]), Integer.parseInt(components[1]),
                Integer.parseInt(components[2]));
        }
        catch (NumberFormatException exception) {
            throw new IllegalArgumentException("Pack version component is too large", exception);
        }
    }

    @Override
    public int compareTo(PackVersion other) {
        int result = Integer.compare(major, other.major);
        if (result == 0) {
            result = Integer.compare(minor, other.minor);
        }
        if (result == 0) {
            result = Integer.compare(patch, other.patch);
        }
        return result;
    }

    @Override
    public String toString() {
        return major + "." + minor + "." + patch;
    }
}
