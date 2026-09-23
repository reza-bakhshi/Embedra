package io.github.rezabakhshi.embedra.pack;

import java.util.Objects;

/** Evidence that SVD addresses were checked against the ESP-IDF header pack. */
public record EspSvdReconciliation(
        String headerPackContentSha256,
        long matchingPeripheralBases,
        long matchingRegisterAddresses,
        String policy) {
    public EspSvdReconciliation {
        Objects.requireNonNull(headerPackContentSha256, "headerPackContentSha256");
        if (!headerPackContentSha256.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("Header-pack digest is invalid");
        }
        if (matchingPeripheralBases < 0 || matchingRegisterAddresses < 0) {
            throw new IllegalArgumentException("Reconciliation counts are negative");
        }
        Objects.requireNonNull(policy, "policy");
        if (!policy.equals("fail-on-shared-name-address-conflict")) {
            throw new IllegalArgumentException("SVD reconciliation policy is unsupported");
        }
    }
}
