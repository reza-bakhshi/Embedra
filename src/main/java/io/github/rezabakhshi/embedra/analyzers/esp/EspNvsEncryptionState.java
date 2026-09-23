package io.github.rezabakhshi.embedra.analyzers.esp;

/** Offline NVS encryption evidence without a claim about active runtime configuration. */
public enum EspNvsEncryptionState {
    KEY_PARTITION_PRESENT,
    ENCRYPTED_PARTITION_INDICATED,
    NOT_INDICATED
}
