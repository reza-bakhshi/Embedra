package io.github.rezabakhshi.embedra.analyzers.crypto.corpus;

/**
 * Standardized taxonomy of technical reasons why a cryptographic primitive or implementation variant
 * is unsupported by the current detector set (AN-012, AN-015).
 */
public enum UnsupportedReason {
    /**
     * Algebraic or bitsliced cipher implementation lacking standard S-box tables or constant sequences.
     */
    CUSTOM_INLINED_WITHOUT_CONSTANTS("Bitsliced / Algebraic Implementation Lacks Static Constants"),

    /**
     * Platform-specific SIMD or vectorized assembly without standard calling convention or compiler idioms.
     */
    VECTORIZED_SIMD_WITHOUT_STANDARD_PROLOGUE("Custom Vectorized SIMD Assembly Without Standard Prologue"),

    /**
     * Proprietary or closed hardware enclave protocol lacking public interface documentation or schemas.
     */
    PROPRIETARY_SECURE_ENCLAVE("Proprietary Hardware Secure Enclave Interface"),

    /**
     * Standalone coprocessor/microengine implementation (e.g. PIO state machine) without host CPU instructions.
     */
    COPROCESSOR_ISOLATED_FIRMWARE("Isolated Coprocessor Microengine Firmware"),

    /**
     * Custom proprietary substitution permutation lacking published reference table.
     */
    NON_STANDARD_SUBSTITUTION_BOX("Non-Standard Proprietary Substitution Permutation"),

    /**
     * Other documented limitation.
     */
    OTHER("Other Documented Unsupported Variant");

    private final String description;

    UnsupportedReason(String description) {
        this.description = description;
    }

    public String description() {
        return description;
    }
}
