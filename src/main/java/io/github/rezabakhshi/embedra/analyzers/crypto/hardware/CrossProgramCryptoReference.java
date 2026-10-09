package io.github.rezabakhshi.embedra.analyzers.crypto.hardware;

import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Cross-program or inter-core cryptographic handoff reference (AN-013).
 *
 * <p>Models shared mailboxes, shared crypto buffer segments, and bootloader-to-application
 * key ladder or validation handoffs between cores or firmware stages.</p>
 *
 * @param referenceId unique reference identifier
 * @param sourceProgram source slot or program identifier (e.g. "bl2", "core0")
 * @param targetProgram destination slot or program identifier (e.g. "tee", "core1")
 * @param sharedAddress base address of shared buffer or mailbox
 * @param lengthBytes buffer size in bytes
 * @param purpose intended crypto handoff purpose (e.g. "KEY_BLOB_HANDOFF", "SECURE_IPC")
 * @param verified true if confirmed by both producer and consumer instructions
 */
public record CrossProgramCryptoReference(
        String referenceId,
        String sourceProgram,
        String targetProgram,
        long sharedAddress,
        int lengthBytes,
        String purpose,
        boolean verified) {

    public CrossProgramCryptoReference {
        Objects.requireNonNull(referenceId, "referenceId must not be null");
        Objects.requireNonNull(sourceProgram, "sourceProgram must not be null");
        Objects.requireNonNull(targetProgram, "targetProgram must not be null");
        Objects.requireNonNull(purpose, "purpose must not be null");
        if (sharedAddress < 0) {
            throw new IllegalArgumentException("sharedAddress must be non-negative: " + sharedAddress);
        }
        if (lengthBytes < 0) {
            throw new IllegalArgumentException("lengthBytes must be non-negative: " + lengthBytes);
        }
    }
}
