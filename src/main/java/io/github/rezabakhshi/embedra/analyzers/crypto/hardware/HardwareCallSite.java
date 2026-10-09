package io.github.rezabakhshi.embedra.analyzers.crypto.hardware;

import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Observed direct or indirect function call instruction site (AN-010, AN-013).
 *
 * @param callAddress address of the call instruction
 * @param targetAddress resolved target address if known, or -1 if indirect
 * @param targetName target symbol name if known
 * @param argumentConstants static constant integer arguments passed to call (e.g. register a0-a3 / r0-r3)
 */
public record HardwareCallSite(
        long callAddress,
        long targetAddress,
        String targetName,
        List<Long> argumentConstants) {

    public HardwareCallSite {
        if (callAddress < 0) {
            throw new IllegalArgumentException("callAddress must be non-negative: " + callAddress);
        }
        targetName = targetName == null ? "" : targetName;
        argumentConstants = argumentConstants == null ? List.of()
                : Collections.unmodifiableList(List.copyOf(argumentConstants));
    }
}
