package io.github.rezabakhshi.embedra.analyzers.crypto.signatures;

/**
 * Compiler family for compiler-aware cryptographic signatures (AN-011).
 */
public enum CryptoCompiler {
    GCC("GNU Compiler Collection (GCC)"),
    CLANG("LLVM Clang"),
    ARMCC("Arm Compiler (armcc / armclang)"),
    IAR("IAR Embedded Workbench"),
    ANY("Any / Unspecified Compiler");

    private final String displayName;

    CryptoCompiler(String displayName) {
        this.displayName = displayName;
    }

    public String displayName() {
        return displayName;
    }
}
