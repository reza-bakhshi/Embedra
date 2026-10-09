package io.github.rezabakhshi.embedra.analyzers.crypto.signatures;

import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoEvidenceLayer;
import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoFinding;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Pure, bounded, ISA/compiler-aware matcher for embedded crypto library signatures (AN-010, AN-011, AN-014).
 */
public final class CryptoLibrarySignatureMatcher {

    private final CryptoSignatureDatabase database;

    public CryptoLibrarySignatureMatcher() {
        this(CryptoSignatureDatabase.defaultDatabase());
    }

    public CryptoLibrarySignatureMatcher(CryptoSignatureDatabase database) {
        this.database = Objects.requireNonNull(database, "database must not be null");
    }

    /**
     * Scans arbitrary byte data for library signatures, hardware wrappers, and inlined idioms.
     */
    public CryptoSignatureMatchReport scan(
            byte[] data,
            long baseAddress,
            CryptoIsa targetIsa,
            ParserLimits limits,
            CancellationToken token) throws DiagnosticException {
        Objects.requireNonNull(data, "data must not be null");
        Objects.requireNonNull(limits, "limits must not be null");
        Objects.requireNonNull(token, "token must not be null");

        token.throwIfCancellationRequested();

        long startNanos = System.nanoTime();
        List<CryptoLibrarySignature> candidateSigs = database.allSignatures().stream()
                .filter(s -> targetIsa == null || s.isa() == targetIsa || s.isa() == CryptoIsa.GENERIC)
                .toList();

        if (candidateSigs.isEmpty()) {
            return new CryptoSignatureMatchReport(List.of(), 0, 0);
        }

        List<CryptoFinding> findings = new ArrayList<>();
        int evaluated = 0;

        int step = (targetIsa == CryptoIsa.ARM_THUMB || targetIsa == CryptoIsa.RISCV32) ? 2 : 1;

        for (int offset = 0; offset < data.length; offset += step) {
            if ((offset & 0x3ff) == 0) {
                token.throwIfCancellationRequested();
                if (System.nanoTime() - startNanos > limits.maxWallTime().toNanos()) {
                    throw new DiagnosticException(Diagnostic.error(
                            DiagnosticCode.LIMIT_EXCEEDED,
                            "Signature scan exceeded time budget", null));
                }
            }

            for (CryptoLibrarySignature sig : candidateSigs) {
                evaluated++;
                if (sig.matches(data, offset)) {
                    long addr = baseAddress + offset;
                    findings.add(toFinding(sig, data, offset, addr));
                    if (findings.size() >= limits.maxObjects()) {
                        break;
                    }
                }
            }

            if (findings.size() >= limits.maxObjects()) {
                break;
            }
        }

        return new CryptoSignatureMatchReport(findings, evaluated, findings.size());
    }

    /**
     * Evaluates a known function entrypoint against the signature database.
     */
    public List<CryptoFinding> matchFunction(
            byte[] functionBytes,
            long functionAddress,
            CryptoIsa targetIsa,
            ParserLimits limits,
            CancellationToken token) throws DiagnosticException {
        Objects.requireNonNull(functionBytes, "functionBytes must not be null");
        Objects.requireNonNull(limits, "limits must not be null");
        Objects.requireNonNull(token, "token must not be null");

        token.throwIfCancellationRequested();

        List<CryptoLibrarySignature> candidateSigs = database.allSignatures().stream()
                .filter(s -> targetIsa == null || s.isa() == targetIsa || s.isa() == CryptoIsa.GENERIC)
                .toList();

        List<CryptoFinding> matches = new ArrayList<>();
        for (CryptoLibrarySignature sig : candidateSigs) {
            token.throwIfCancellationRequested();
            if (sig.matches(functionBytes, 0)) {
                matches.add(toFinding(sig, functionBytes, 0, functionAddress));
            }
        }
        return Collections.unmodifiableList(matches);
    }

    private static CryptoFinding toFinding(
            CryptoLibrarySignature sig,
            byte[] data,
            int offset,
            long address) {

        int len = sig.length();
        byte[] matchedSlice = Arrays.copyOfRange(data, offset, offset + len);
        String rawHex = HexFormat.of().formatHex(matchedSlice);

        Set<CryptoEvidenceLayer> layers = new HashSet<>();
        layers.add(CryptoEvidenceLayer.FUNCTION_SIGNATURE);
        if (sig.role() == CryptoArtifactRole.INLINED_IDIOM) {
            layers.add(CryptoEvidenceLayer.INSTRUCTION_IDIOM);
        }

        String explanation = String.format("[%s %s (%s)] %s in %s (%s, %s)",
                sig.library().displayName(),
                sig.provenance().version(),
                sig.role().displayName(),
                sig.name(),
                sig.isa().displayName(),
                sig.compiler().displayName(),
                sig.optimization().displayName());

        Map<String, String> attrs = new HashMap<>();
        attrs.put("crypto.library", sig.library().name());
        attrs.put("crypto.library.display", sig.library().displayName());
        attrs.put("crypto.library.version", sig.provenance().version());
        attrs.put("crypto.library.license", sig.provenance().license());
        attrs.put("crypto.artifact.role", sig.role().name());
        attrs.put("crypto.isa", sig.isa().name());
        attrs.put("crypto.compiler", sig.compiler().name());
        attrs.put("crypto.optimization", sig.optimization().name());
        attrs.put("crypto.signature.id", sig.id());
        attrs.put("crypto.source.file", sig.provenance().sourceFile());
        attrs.put("crypto.source.sha256", sig.provenance().sourceSha256());
        if (!sig.crossReferenceSymbols().isEmpty()) {
            attrs.put("crypto.symbols", String.join(", ", sig.crossReferenceSymbols()));
        }

        boolean secret = sig.role() == CryptoArtifactRole.SECRET_KEY_CANDIDATE;
        String id = "crypto-sig-" + sig.id() + "-" + Long.toHexString(address);

        return new CryptoFinding(
                id,
                address,
                len,
                sig.algorithm().defaultCategory(),
                sig.algorithm(),
                sig.confidence(),
                layers,
                explanation,
                rawHex,
                secret,
                attrs
        );
    }
}
