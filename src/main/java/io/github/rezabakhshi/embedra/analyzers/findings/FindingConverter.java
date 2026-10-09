package io.github.rezabakhshi.embedra.analyzers.findings;

import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoFinding;
import io.github.rezabakhshi.embedra.analyzers.ctf.CtfEntity;
import io.github.rezabakhshi.embedra.analyzers.leads.SecurityLead;
import io.github.rezabakhshi.embedra.analyzers.logging.LoggingCallSite;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Pure converter translating domain findings into canonical {@link UnifiedFinding} instances (AN-006).
 */
public final class FindingConverter {

    private FindingConverter() {
    }

    /**
     * Converts a CTF entity into a unified finding.
     */
    public static UnifiedFinding fromCtfEntity(CtfEntity entity, String platform) {
        Objects.requireNonNull(entity, "entity must not be null");

        FindingSeverity sev = switch (entity.severity()) {
            case HIGH -> FindingSeverity.HIGH;
            case MEDIUM -> FindingSeverity.MEDIUM;
            case LOW -> FindingSeverity.LOW;
            case INFO -> FindingSeverity.INFO;
        };

        FindingConfidence conf = switch (entity.confidence()) {
            case CONFIRMED -> FindingConfidence.CONFIRMED;
            case LIKELY -> FindingConfidence.LIKELY;
            case PLAUSIBLE -> FindingConfidence.PLAUSIBLE;
        };

        double score = switch (entity.confidence()) {
            case CONFIRMED -> 0.90;
            case LIKELY -> 0.65;
            case PLAUSIBLE -> 0.40;
        };

        return new UnifiedFinding(
                entity.id(),
                FindingCategory.CTF_ENTITY,
                entity.type().name(),
                sev,
                conf,
                score,
                platform,
                entity.address(),
                entity.length(),
                entity.value(),
                entity.explanation(),
                entity.secret(),
                false,
                null,
                entity.attributes());
    }

    /**
     * Converts a cryptographic finding into a unified finding.
     */
    public static UnifiedFinding fromCryptoFinding(CryptoFinding finding, String platform) {
        Objects.requireNonNull(finding, "finding must not be null");

        FindingSeverity sev = switch (finding.category()) {
            case KEY_MATERIAL -> FindingSeverity.CRITICAL;
            case CIPHER_SYMMETRIC, CIPHER_ASYMMETRIC, CERTIFICATE, HARDWARE_SECURITY -> FindingSeverity.HIGH;
            case HASH_MAC, RANDOM_GENERATOR -> FindingSeverity.MEDIUM;
            case CHECKSUM_CRC, ENCODING_OR_COMPRESSION, ENTROPY_ANOMALY -> FindingSeverity.LOW;
        };

        FindingConfidence conf = switch (finding.confidence()) {
            case CONFIRMED -> FindingConfidence.CONFIRMED;
            case LIKELY -> FindingConfidence.LIKELY;
            case PLAUSIBLE -> FindingConfidence.PLAUSIBLE;
            case LEAD -> FindingConfidence.LEAD;
        };

        double score = switch (finding.confidence()) {
            case CONFIRMED -> 0.95;
            case LIKELY -> 0.75;
            case PLAUSIBLE -> 0.50;
            case LEAD -> 0.25;
        };

        return new UnifiedFinding(
                finding.id(),
                FindingCategory.CRYPTOGRAPHY,
                finding.algorithm().name(),
                sev,
                conf,
                score,
                platform,
                finding.address(),
                finding.length(),
                finding.rawValue(),
                finding.explanation(),
                finding.secret(),
                false,
                null,
                finding.attributes());
    }

    /**
     * Converts a logging call site into a unified finding.
     */
    public static UnifiedFinding fromLoggingCallSite(LoggingCallSite site, String platform) {
        Objects.requireNonNull(site, "site must not be null");

        FindingSeverity sev = switch (site.level()) {
            case PANIC -> FindingSeverity.CRITICAL;
            case ASSERT, ERROR -> FindingSeverity.HIGH;
            case WARNING -> FindingSeverity.MEDIUM;
            case INFO, DEBUG -> FindingSeverity.INFO;
        };

        FindingConfidence conf = switch (site.confidence().toUpperCase(java.util.Locale.ROOT)) {
            case "CONFIRMED" -> FindingConfidence.CONFIRMED;
            case "LIKELY" -> FindingConfidence.LIKELY;
            default -> FindingConfidence.PLAUSIBLE;
        };

        double score = switch (conf) {
            case CONFIRMED -> 0.95;
            case LIKELY -> 0.75;
            case PLAUSIBLE -> 0.50;
            case LEAD -> 0.25;
        };

        String id = String.format("LOG-%08X", site.callInstructionAddress());
        String target = site.targetSymbol() != null && !site.targetSymbol().isBlank()
                ? site.targetSymbol() : "0x" + Long.toHexString(site.targetFunctionAddress());

        Map<String, String> attrs = new HashMap<>(site.argumentReferences());
        if (site.formatString() != null) {
            attrs.put("formatString", site.formatString().rawText());
        }

        return new UnifiedFinding(
                id,
                FindingCategory.LOGGING_DIAGNOSTIC,
                site.level().name(),
                sev,
                conf,
                score,
                platform,
                site.callInstructionAddress(),
                4,
                target,
                site.explanation(),
                false,
                false,
                null,
                attrs);
    }

    /**
     * Converts a candidate security lead into a unified finding.
     */
    public static UnifiedFinding fromSecurityLead(SecurityLead lead, String platform) {
        Objects.requireNonNull(lead, "lead must not be null");

        FindingSeverity sev = switch (lead.severity()) {
            case CRITICAL -> FindingSeverity.CRITICAL;
            case HIGH -> FindingSeverity.HIGH;
            case MEDIUM -> FindingSeverity.MEDIUM;
            case LOW -> FindingSeverity.LOW;
            case INFO -> FindingSeverity.INFO;
        };

        FindingConfidence conf = switch (lead.confidence()) {
            case HIGH -> FindingConfidence.CONFIRMED;
            case MEDIUM -> FindingConfidence.LIKELY;
            case LOW -> FindingConfidence.LEAD;
        };

        return new UnifiedFinding(
                lead.id(),
                FindingCategory.SECURITY_LEAD,
                lead.category().name(),
                sev,
                conf,
                lead.confidenceScore(),
                platform,
                lead.address(),
                4,
                lead.target(),
                lead.description(),
                lead.secret(),
                false,
                null,
                lead.attributes());
    }
}
