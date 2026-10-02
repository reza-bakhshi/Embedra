package io.github.rezabakhshi.embedra.analyzers.stm32;

import io.github.rezabakhshi.embedra.core.model.Confidence;
import io.github.rezabakhshi.embedra.core.model.Evidence;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.OptionalLong;

/**
 * Redacted STM32 CTF lead with stable code, bounded severity, and evidence.
 *
 * <p>A lead is a provenance-bearing analysis hint, never a device-support or
 * exploitability claim. The code namespace is {@code STM32_*}; severity is a
 * closed deterministic set so ranking stays reproducible; every lead carries at
 * least one evidence entry from its shared-analyzer source. Secret-bearing
 * export redaction follows the shared T025 rule: a lead marked secret must not
 * carry key or payload material, and no T048 detector produces secret material
 * at all.</p>
 */
public record Stm32CtfLead(
        String code,
        Severity severity,
        Confidence confidence,
        String explanation,
        OptionalLong address,
        boolean secret,
        List<Evidence> evidence) {

    /** Closed deterministic severity set used for lead ranking. */
    public enum Severity {
        HIGH,
        MEDIUM,
        LOW,
        INFO
    }

    public Stm32CtfLead {
        Objects.requireNonNull(code, "code");
        Objects.requireNonNull(severity, "severity");
        Objects.requireNonNull(confidence, "confidence");
        Objects.requireNonNull(explanation, "explanation");
        Objects.requireNonNull(address, "address");
        evidence = List.copyOf(evidence);
        if (!code.matches("STM32_[A-Z0-9_]+") || explanation.isBlank()
                || evidence.isEmpty()) {
            throw new IllegalArgumentException("Invalid STM32 CTF lead");
        }
    }

    /** True when this lead carries secret-bearing material for export redaction. */
    public boolean requiresSecretRedaction() {
        return secret;
    }

    static int rank(Severity severity) {
        return switch (severity) {
            case HIGH -> 3;
            case MEDIUM -> 2;
            case LOW -> 1;
            case INFO -> 0;
        };
    }

    /** Hexadecimal rendering used in deterministic explanations. */
    static String hex(long address) {
        return "0x" + Long.toHexString(address).toUpperCase(Locale.ROOT);
    }
}
