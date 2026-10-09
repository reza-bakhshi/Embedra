package io.github.rezabakhshi.embedra.analyzers.crypto.tables;

import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoAlgorithm;
import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoCategory;
import java.util.Arrays;
import java.util.Objects;

/**
 * Signature representing a known cryptographic constant or lookup table.
 */
public final class CryptoTableSignature {
    private final String id;

    private final String name;

    private final CryptoCategory category;

    private final CryptoAlgorithm algorithm;

    private final byte[] pattern;

    private final int minMatchLength;

    private final String explanation;

    public CryptoTableSignature(
            String id,
            String name,
            CryptoCategory category,
            CryptoAlgorithm algorithm,
            byte[] pattern,
            int minMatchLength,
            String explanation) {
        this.id = Objects.requireNonNull(id, "id must not be null");
        this.name = Objects.requireNonNull(name, "name must not be null");
        this.category = Objects.requireNonNull(category, "category must not be null");
        this.algorithm = Objects.requireNonNull(algorithm, "algorithm must not be null");
        Objects.requireNonNull(pattern, "pattern must not be null");
        if (pattern.length == 0) {
            throw new IllegalArgumentException("Pattern must not be empty");
        }
        if (minMatchLength <= 0 || minMatchLength > pattern.length) {
            throw new IllegalArgumentException("Invalid minMatchLength: " + minMatchLength);
        }
        this.pattern = Arrays.copyOf(pattern, pattern.length);
        this.minMatchLength = minMatchLength;
        this.explanation = Objects.requireNonNull(explanation, "explanation must not be null");
    }

    public CryptoTableSignature(
            String id,
            String name,
            CryptoCategory category,
            CryptoAlgorithm algorithm,
            byte[] pattern,
            String explanation) {
        this(id, name, category, algorithm, pattern, pattern.length, explanation);
    }

    public String id() {
        return id;
    }

    public String name() {
        return name;
    }

    public CryptoCategory category() {
        return category;
    }

    public CryptoAlgorithm algorithm() {
        return algorithm;
    }

    public byte[] pattern() {
        return Arrays.copyOf(pattern, pattern.length);
    }

    public int patternLength() {
        return pattern.length;
    }

    public int minMatchLength() {
        return minMatchLength;
    }

    public String explanation() {
        return explanation;
    }

    /**
     * Checks if the pattern matches the data slice starting at the given offset.
     */
    public boolean matches(byte[] data, int offset) {
        if (offset < 0 || offset + minMatchLength > data.length) {
            return false;
        }
        for (int i = 0; i < minMatchLength; i++) {
            if (data[offset + i] != pattern[i]) {
                return false;
            }
        }
        return true;
    }
}
