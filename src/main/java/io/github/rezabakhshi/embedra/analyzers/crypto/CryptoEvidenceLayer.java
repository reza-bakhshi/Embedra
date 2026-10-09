package io.github.rezabakhshi.embedra.analyzers.crypto;

/**
 * Contributing evidence layer in the layered cryptographic analysis pipeline (AN-010).
 *
 * <p>Findings retain which layers contributed to detection and confidence scoring.</p>
 */
public enum CryptoEvidenceLayer {
    /**
     * Exact table or constant matching (e.g. S-boxes, permutation tables, round constants).
     */
    CONSTANT_TABLE("Constant or Table Signature"),

    /**
     * Exact symbols, imports, or debug strings referencing algorithm or library names.
     */
    SYMBOL_STRING("Symbol or Debug String"),

    /**
     * Hardware peripheral register access or memory-mapped I/O (e.g. STM32 CRYP, ESP32 AES).
     */
    HARDWARE_PERIPHERAL("Hardware Peripheral Access"),

    /**
     * Architecture-specific instruction idioms or assembly sequences.
     */
    INSTRUCTION_IDIOM("Instruction Idiom"),

    /**
     * Statistical sliding-window entropy or chi-squared distribution metric.
     */
    ENTROPY_METRIC("Entropy Metric"),

    /**
     * Inter-procedural call-graph or data-flow correlation.
     */
    DATA_FLOW("Data Flow Correlation"),

    /**
     * Compiler/optimization/ISA-aware library function or idiom signature (AN-010, AN-011).
     */
    FUNCTION_SIGNATURE("Library Function Signature"),

    /**
     * Vendor ROM API function call or resolved table vector (AN-010, AN-013).
     */
    ROM_API("Vendor ROM API Call"),

    /**
     * Hardware security configuration (eFuse, OTP, Secure Boot, Flash Encryption) (AN-013).
     */
    HARDWARE_CONFIG("Hardware Security Configuration");

    private final String displayName;

    CryptoEvidenceLayer(String displayName) {
        this.displayName = displayName;
    }

    public String displayName() {
        return displayName;
    }
}
