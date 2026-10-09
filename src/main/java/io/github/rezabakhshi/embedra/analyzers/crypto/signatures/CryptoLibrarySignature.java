package io.github.rezabakhshi.embedra.analyzers.crypto.signatures;

import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoAlgorithm;
import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoConfidence;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Provenance-checked, compiler/optimization/ISA-aware signature for an embedded cryptographic
 * function, wrapper, or inlined variant (AN-010, AN-011, AN-014).
 */
public final class CryptoLibrarySignature {

    public static final int MIN_PATTERN_BYTES = 8;

    public static final int MAX_PATTERN_BYTES = 65_536;

    public static final int MIN_SIGNIFICANT_BYTES = 4;

    private final String id;

    private final String name;

    private final CryptoLibrary library;

    private final CryptoAlgorithm algorithm;

    private final CryptoArtifactRole role;

    private final CryptoIsa isa;

    private final CryptoCompiler compiler;

    private final CryptoOptimization optimization;

    private final CryptoConfidence confidence;

    private final CryptoSignatureProvenance provenance;

    private final byte[] pattern;

    private final byte[] mask;

    private final List<String> crossReferenceSymbols;

    public CryptoLibrarySignature(
            String id,
            String name,
            CryptoLibrary library,
            CryptoAlgorithm algorithm,
            CryptoArtifactRole role,
            CryptoIsa isa,
            CryptoCompiler compiler,
            CryptoOptimization optimization,
            CryptoConfidence confidence,
            CryptoSignatureProvenance provenance,
            byte[] pattern,
            byte[] mask,
            List<String> crossReferenceSymbols) {
        this.id = Objects.requireNonNull(id, "id must not be null");
        this.name = Objects.requireNonNull(name, "name must not be null");
        this.library = Objects.requireNonNull(library, "library must not be null");
        this.algorithm = Objects.requireNonNull(algorithm, "algorithm must not be null");
        this.role = Objects.requireNonNull(role, "role must not be null");
        this.isa = Objects.requireNonNull(isa, "isa must not be null");
        this.compiler = Objects.requireNonNull(compiler, "compiler must not be null");
        this.optimization = Objects.requireNonNull(optimization, "optimization must not be null");
        this.confidence = Objects.requireNonNull(confidence, "confidence must not be null");
        this.provenance = Objects.requireNonNull(provenance, "provenance must not be null");
        Objects.requireNonNull(pattern, "pattern must not be null");
        Objects.requireNonNull(mask, "mask must not be null");

        if (id.isBlank()) {
            throw new IllegalArgumentException("id must not be blank");
        }
        if (name.isBlank()) {
            throw new IllegalArgumentException("name must not be blank");
        }
        if (pattern.length < MIN_PATTERN_BYTES || pattern.length > MAX_PATTERN_BYTES) {
            throw new IllegalArgumentException("pattern length must be between "
                    + MIN_PATTERN_BYTES + " and " + MAX_PATTERN_BYTES + ": " + pattern.length);
        }
        if (pattern.length != mask.length) {
            throw new IllegalArgumentException("pattern and mask lengths must match: "
                    + pattern.length + " vs " + mask.length);
        }

        int significantCount = 0;
        for (byte m : mask) {
            if (m != 0 && m != (byte) 0xff) {
                throw new IllegalArgumentException("mask bytes must be 0x00 (wildcard) or 0xff (exact)");
            }
            if (m == (byte) 0xff) {
                significantCount++;
            }
        }
        if (significantCount < MIN_SIGNIFICANT_BYTES) {
            throw new IllegalArgumentException("mask must have at least "
                    + MIN_SIGNIFICANT_BYTES + " significant bytes, found " + significantCount);
        }

        this.pattern = pattern.clone();
        this.mask = mask.clone();
        this.crossReferenceSymbols = crossReferenceSymbols == null
                ? List.of()
                : Collections.unmodifiableList(List.copyOf(crossReferenceSymbols));
    }

    public String id() {
        return id;
    }

    public String name() {
        return name;
    }

    public CryptoLibrary library() {
        return library;
    }

    public CryptoAlgorithm algorithm() {
        return algorithm;
    }

    public CryptoArtifactRole role() {
        return role;
    }

    public CryptoIsa isa() {
        return isa;
    }

    public CryptoCompiler compiler() {
        return compiler;
    }

    public CryptoOptimization optimization() {
        return optimization;
    }

    public CryptoConfidence confidence() {
        return confidence;
    }

    public CryptoSignatureProvenance provenance() {
        return provenance;
    }

    public byte[] pattern() {
        return pattern.clone();
    }

    public byte[] mask() {
        return mask.clone();
    }

    public int length() {
        return pattern.length;
    }

    public List<String> crossReferenceSymbols() {
        return crossReferenceSymbols;
    }

    /**
     * Checks if the pattern matches bytes in data at offset.
     */
    public boolean matches(byte[] data, int offset) {
        if (data == null || offset < 0 || offset + pattern.length > data.length) {
            return false;
        }
        for (int i = 0; i < pattern.length; i++) {
            if (mask[i] != 0 && (data[offset + i] & mask[i]) != (pattern[i] & mask[i])) {
                return false;
            }
        }
        return true;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof CryptoLibrarySignature that)) {
            return false;
        }
        return Objects.equals(id, that.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }

    @Override
    public String toString() {
        return "CryptoLibrarySignature[" + id + " (" + library + "/" + name + ")]";
    }
}
