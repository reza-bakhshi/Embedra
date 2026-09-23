package io.github.rezabakhshi.embedra.analyzers.esp;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.core.model.Confidence;
import io.github.rezabakhshi.embedra.core.model.Evidence;
import io.github.rezabakhshi.embedra.core.model.EvidenceKind;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.OptionalLong;

/** Conservative ESP32-S3 hardware-crypto and resolved ROM API use detector. */
public final class EspHardwareCryptoAnalyzer {
    private static final long AES_MODE = 0x6003_a040L;

    private static final long AES_TRIGGER = 0x6003_a048L;

    private static final long AES_BLOCK_MODE = 0x6003_a064L;

    private static final long SHA_MODE = 0x6003_b000L;

    private static final long SHA_START = 0x6003_b010L;

    private static final List<String> DETECTORS = List.of(
        "esp32s3-aes-mmio", "esp32s3-ds-mmio", "esp32s3-hmac-mmio",
        "esp32s3-rsa-mmio", "esp32s3-sha-mmio", "esp32s3-xts-aes-mmio");

    private static final List<String> UNSUPPORTED = List.of(
        "software-crypto-without-versioned-signature",
        "unresolved-indirect-crypto-calls",
        "runtime-derived-mmio-addresses",
        "secret-key-verification");

    public EspHardwareCryptoReport analyze(List<EspMemoryAccessFact> accesses,
            ParserLimits limits, CancellationToken token) throws DiagnosticException {
        return analyze(accesses, List.of(), limits, token);
    }

    public EspHardwareCryptoReport analyze(List<EspMemoryAccessFact> accesses,
            List<EspCryptoCallFact> calls, ParserLimits limits,
            CancellationToken token) throws DiagnosticException {
        Objects.requireNonNull(accesses, "accesses");
        Objects.requireNonNull(calls, "calls");
        Objects.requireNonNull(limits, "limits");
        Objects.requireNonNull(token, "token");
        token.throwIfCancellationRequested();
        if ((long) accesses.size() + calls.size() > limits.maxObjects()) {
            throw new DiagnosticException(Diagnostic.error(DiagnosticCode.LIMIT_EXCEEDED,
                "Crypto analysis exceeds the configured object limit", null));
        }
        List<EspMemoryAccessFact> ordered = accesses.stream()
            .sorted(Comparator.comparingLong(EspMemoryAccessFact::instructionAddress))
            .toList();
        Map<Long, OptionalLong> writes = new HashMap<>();
        List<EspHardwareCryptoFinding> findings = new ArrayList<>();
        for (EspMemoryAccessFact access : ordered) {
            token.throwIfCancellationRequested();
            if (access.kind() != EspMemoryAccessKind.WRITE) {
                continue;
            }
            writes.put(access.targetAddress(), access.resolvedValue());
            if (access.targetAddress() == AES_TRIGGER && isOne(access.resolvedValue())) {
                addAesFinding(access, writes, findings);
            }
            else if (access.targetAddress() == SHA_START
                    && isOne(access.resolvedValue())) {
                addShaFinding(access, writes, findings);
            }
        }
        for (EspCryptoCallFact call : calls.stream()
                .sorted(Comparator.comparingLong(EspCryptoCallFact::callAddress)).toList()) {
            token.throwIfCancellationRequested();
            String algorithm = romAlgorithm(call.targetName());
            if (algorithm != null) {
                findings.add(new EspHardwareCryptoFinding(call.callAddress(), algorithm,
                    EspCryptoEvidenceKind.ROM_API_CALLER, Confidence.DERIVED,
                    List.of(new Evidence(EvidenceKind.VENDOR_DATA_PACK, call.provenance(),
                        "Resolved call to " + call.targetName()))));
            }
        }
        findings.sort(Comparator.comparingLong(EspHardwareCryptoFinding::address)
            .thenComparing(EspHardwareCryptoFinding::algorithm));
        return new EspHardwareCryptoReport(findings, DETECTORS, UNSUPPORTED);
    }

    private static void addAesFinding(EspMemoryAccessFact trigger,
            Map<Long, OptionalLong> writes, List<EspHardwareCryptoFinding> findings) {
        OptionalLong mode = resolved(writes, AES_MODE);
        OptionalLong block = resolved(writes, AES_BLOCK_MODE);
        if (mode.isEmpty() || block.isEmpty()) {
            return;
        }
        String keyMode = switch ((int) mode.getAsLong()) {
            case 0 -> "AES-128-ENCRYPT";
            case 1 -> "AES-192-ENCRYPT";
            case 2 -> "AES-256-ENCRYPT";
            case 4 -> "AES-128-DECRYPT";
            case 5 -> "AES-192-DECRYPT";
            case 6 -> "AES-256-DECRYPT";
            default -> null;
        };
        String blockMode = switch ((int) block.getAsLong()) {
            case 0 -> "ECB";
            case 1 -> "CBC";
            case 2 -> "OFB";
            case 3 -> "CTR";
            case 4 -> "CFB-8";
            case 5 -> "CFB-128";
            case 6 -> "GCM";
            default -> null;
        };
        if (keyMode == null || blockMode == null) {
            return;
        }
        String algorithm = keyMode.replace("-ENCRYPT", "")
            .replace("-DECRYPT", "") + "-" + blockMode;
        findings.add(mmioFinding(trigger, algorithm,
            "Resolved AES mode, block mode, and trigger writes"));
    }

    private static void addShaFinding(EspMemoryAccessFact trigger,
            Map<Long, OptionalLong> writes, List<EspHardwareCryptoFinding> findings) {
        OptionalLong mode = resolved(writes, SHA_MODE);
        if (mode.isEmpty()) {
            return;
        }
        String algorithm = switch ((int) mode.getAsLong()) {
            case 0 -> "SHA-1";
            case 1 -> "SHA-224";
            case 2 -> "SHA-256";
            case 3 -> "SHA-384";
            case 4 -> "SHA-512";
            case 5 -> "SHA-512/224";
            case 6 -> "SHA-512/256";
            case 7 -> "SHA-512/t";
            default -> null;
        };
        if (algorithm != null) {
            findings.add(mmioFinding(trigger, algorithm,
                "Resolved SHA mode and start-register writes"));
        }
    }

    private static EspHardwareCryptoFinding mmioFinding(EspMemoryAccessFact trigger,
            String algorithm, String detail) {
        return new EspHardwareCryptoFinding(trigger.instructionAddress(), algorithm,
            EspCryptoEvidenceKind.HARDWARE_ACCELERATOR_USE, Confidence.DERIVED,
            List.of(new Evidence(EvidenceKind.DERIVED_RULE,
                "espressif-svd:esp32s3", detail)));
    }

    private static OptionalLong resolved(Map<Long, OptionalLong> writes, long address) {
        return writes.getOrDefault(address, OptionalLong.empty());
    }

    private static boolean isOne(OptionalLong value) {
        return value.isPresent() && value.getAsLong() == 1;
    }

    private static String romAlgorithm(String name) {
        String normalized = name.toLowerCase(Locale.ROOT);
        if (normalized.contains("sha256") || normalized.contains("sha_256")) {
            return "SHA-256";
        }
        if (normalized.contains("sha512") || normalized.contains("sha_512")) {
            return "SHA-512";
        }
        if (normalized.contains("sha1") || normalized.contains("sha_1")) {
            return "SHA-1";
        }
        if (normalized.contains("hmac")) {
            return "HMAC";
        }
        if (normalized.contains("aes")) {
            return "AES";
        }
        if (normalized.contains("rsa")) {
            return "RSA";
        }
        return null;
    }
}
