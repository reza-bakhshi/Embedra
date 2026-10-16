package io.github.rezabakhshi.embedra.analyzers.atmel;

import java.util.Objects;

/**
 * One compiler/optimization/architecture-indexed masked byte signature from a curated Atmel/Microchip runtime pack.
 *
 * <p>Supports Arduino core libraries, AVR-libc runtime, Atmel START / ASF drivers, and FreeRTOS across
 * AVR 8-bit and SAM 32-bit ARM Cortex-M families.</p>
 */
public final class AtmelLibrarySignature {

    public static final int MAX_PATTERN_BYTES = 65_536;

    private final String signatureId;

    private final String library;

    private final String subsystem;

    private final String functionName;

    private final String architecture;

    private final String series;

    private final String compiler;

    private final String optimization;

    private final String sourceFile;

    private final String sourceSha256;

    private final byte[] pattern;

    private final byte[] mask;

    public AtmelLibrarySignature(
            String signatureId,
            String library,
            String subsystem,
            String functionName,
            String architecture,
            String series,
            String compiler,
            String optimization,
            String sourceFile,
            String sourceSha256,
            byte[] pattern,
            byte[] mask) {
        this.signatureId = requireText(signatureId, "signatureId");
        this.library = requireText(library, "library");
        this.subsystem = requireText(subsystem, "subsystem");
        this.functionName = requireText(functionName, "functionName");
        this.architecture = requireText(architecture, "architecture");
        this.series = requireText(series, "series");
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

    public String subsystem() {
        return subsystem;
    }

    public String functionName() {
        return functionName;
    }

    public String architecture() {
        return architecture;
    }

    public String series() {
        return series;
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

    public boolean matches(byte[] functionBytes) {
        if (functionBytes == null || functionBytes.length < pattern.length) {
            return false;
        }
        for (int i = 0; i < pattern.length; i++) {
            if ((functionBytes[i] & mask[i]) != (pattern[i] & mask[i])) {
                return false;
            }
        }
        return true;
    }

    public boolean isFullySpecified() {
        for (byte value : mask) {
            if (value != (byte) 0xff) {
                return false;
            }
        }
        return true;
    }

    private static String requireText(String value, String field) {
        Objects.requireNonNull(value, field);
        if (value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
        return value;
    }
}
