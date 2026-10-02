package io.github.rezabakhshi.embedra.analyzers.stm32;

import java.util.Objects;

/**
 * One compiler/optimization/family-indexed masked byte signature from a
 * digest-pinned STM32 library pack.
 *
 * <p>The pattern is the raw instruction prefix of one compiled function; the
 * mask marks the bytes that a linker relocation may change. A signature is a
 * fact about one source/compiler/optimization combination and never encodes a
 * device-support claim.</p>
 */
public final class Stm32LibrarySignature {
    /** Maximum accepted pattern length; larger payloads are malformed. */
    public static final int MAX_PATTERN_BYTES = 65_536;

    private final String signatureId;

    private final String library;

    private final String component;

    private final String functionName;

    private final String family;

    private final String compiler;

    private final String optimization;

    private final String sourceFile;

    private final String sourceSha256;

    private final byte[] pattern;

    private final byte[] mask;

    public Stm32LibrarySignature(String signatureId, String library, String component,
            String functionName, String family, String compiler, String optimization,
            String sourceFile, String sourceSha256, byte[] pattern, byte[] mask) {
        this.signatureId = requireText(signatureId, "signatureId");
        this.library = requireText(library, "library");
        this.component = requireText(component, "component");
        this.functionName = requireText(functionName, "functionName");
        this.family = requireText(family, "family");
        this.compiler = requireText(compiler, "compiler");
        this.optimization = requireText(optimization, "optimization");
        this.sourceFile = requireText(sourceFile, "sourceFile");
        this.sourceSha256 = requireText(sourceSha256, "sourceSha256");
        if (!this.sourceSha256.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("Signature source digest must be lowercase SHA-256");
        }
        this.pattern = Objects.requireNonNull(pattern, "pattern").clone();
        this.mask = Objects.requireNonNull(mask, "mask").clone();
        if (this.pattern.length < 8 || this.pattern.length != this.mask.length
                || this.pattern.length > MAX_PATTERN_BYTES) {
            throw new IllegalArgumentException("Signature pattern and mask lengths are invalid");
        }
        boolean significant = false;
        for (byte value : this.mask) {
            if (value != 0 && value != (byte) 0xff) {
                throw new IllegalArgumentException("Signature masks must contain only 00 or ff");
            }
            significant |= value != 0;
        }
        if (!significant) {
            throw new IllegalArgumentException("Signature must contain significant bytes");
        }
    }

    public String signatureId() {
        return signatureId;
    }

    public String library() {
        return library;
    }

    public String component() {
        return component;
    }

    public String functionName() {
        return functionName;
    }

    public String family() {
        return family;
    }

    public String compiler() {
        return compiler;
    }

    public String optimization() {
        return optimization;
    }

    public String sourceFile() {
        return sourceFile;
    }

    public String sourceSha256() {
        return sourceSha256;
    }

    public byte[] pattern() {
        return pattern.clone();
    }

    public byte[] mask() {
        return mask.clone();
    }

    boolean isFullySpecified() {
        for (byte value : mask) {
            if (value != (byte) 0xff) {
                return false;
            }
        }
        return true;
    }

    boolean matches(byte[] candidate) {
        if (candidate.length < pattern.length) {
            return false;
        }
        for (int index = 0; index < pattern.length; index++) {
            if ((candidate[index] & mask[index]) != (pattern[index] & mask[index])) {
                return false;
            }
        }
        return true;
    }

    private static String requireText(String value, String name) {
        Objects.requireNonNull(value, name);
        if (value.isBlank()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
        return value;
    }
}
