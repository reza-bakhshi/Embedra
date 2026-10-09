package io.github.rezabakhshi.embedra.analyzers.crypto.signatures;

/**
 * Optimization level for compiler-aware cryptographic signatures (AN-011).
 */
public enum CryptoOptimization {
    O0("O0 (No Optimization)"),
    O1("O1 (Basic Optimization)"),
    O2("O2 (Standard Optimization)"),
    O3("O3 (Aggressive Optimization)"),
    Os("Os (Size Optimization)"),
    Oz("Oz (Extreme Size Optimization)"),
    ANY("Any / Unspecified Optimization");

    private final String displayName;

    CryptoOptimization(String displayName) {
        this.displayName = displayName;
    }

    public String displayName() {
        return displayName;
    }
}
