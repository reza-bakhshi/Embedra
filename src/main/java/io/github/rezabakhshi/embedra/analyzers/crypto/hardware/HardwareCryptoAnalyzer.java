package io.github.rezabakhshi.embedra.analyzers.crypto.hardware;

import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoAlgorithm;
import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoCategory;
import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoConfidence;
import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoEvidenceLayer;
import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoFinding;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Set;

/**
 * Pure analyzer engine evaluating hardware peripheral registers, vendor ROM routines,
 * secure elements, and cross-program crypto data-flows (AN-010, AN-013, AN-014).
 *
 * <p>Enforces AN-013 requirement: peripheral register access is a lead until the operation,
 * mode, and data flow are corroborated by evidence.</p>
 */
public final class HardwareCryptoAnalyzer {

    public HardwareCryptoReport analyze(
            HardwareCryptoPlatform platform,
            List<HardwareMemoryAccess> accesses,
            List<HardwareCallSite> callSites,
            List<CrossProgramCryptoReference> crossProgramRefs,
            ParserLimits limits,
            CancellationToken token) throws DiagnosticException {

        Objects.requireNonNull(platform, "platform must not be null");
        Objects.requireNonNull(limits, "limits must not be null");
        Objects.requireNonNull(token, "token must not be null");

        token.throwIfCancellationRequested();

        List<HardwareMemoryAccess> safeAccesses = accesses == null ? List.of() : List.copyOf(accesses);
        List<HardwareCallSite> safeCalls = callSites == null ? List.of() : List.copyOf(callSites);
        List<CrossProgramCryptoReference> safeCrossRefs = crossProgramRefs == null
                ? List.of() : List.copyOf(crossProgramRefs);

        if ((long) safeAccesses.size() + safeCalls.size() + safeCrossRefs.size() > limits.maxObjects()) {
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.CRYPTO_CALLGRAPH_EXCEEDED,
                    "Hardware crypto analysis exceeded max object limit", null));
        }

        List<CryptoFinding> findings = new ArrayList<>();
        int detectorCount = 0;

        // 1. Analyze hardware MMIO peripheral accesses
        detectorCount += analyzePeripheralAccesses(safeAccesses, findings, limits, token);

        // 2. Analyze vendor ROM and API call sites
        detectorCount += analyzeCallSites(safeCalls, findings, limits, token);

        // 3. Analyze secure elements
        detectorCount += analyzeSecureElements(safeCalls, safeAccesses, findings, limits, token);

        // 4. Analyze cross-program crypto references
        detectorCount += analyzeCrossProgramReferences(safeCrossRefs, findings, limits, token);

        // Sort findings deterministically by address, then algorithm
        findings.sort(Comparator.comparingLong(CryptoFinding::address)
                .thenComparing(f -> f.algorithm().name()));

        return new HardwareCryptoReport(List.copyOf(findings), detectorCount);
    }

    private int analyzePeripheralAccesses(
            List<HardwareMemoryAccess> accesses,
            List<CryptoFinding> findings,
            ParserLimits limits,
            CancellationToken token) throws DiagnosticException {

        Map<Long, OptionalLong> writesByTarget = new HashMap<>();
        List<HardwareMemoryAccess> ordered = accesses.stream()
                .sorted(Comparator.comparingLong(HardwareMemoryAccess::instructionAddress))
                .toList();

        int detections = 0;

        for (HardwareMemoryAccess access : ordered) {
            token.throwIfCancellationRequested();

            if (!access.write()) {
                // Read access alone is a weak lead (AN-013: peripheral register access is a lead)
                Optional<HardwarePeripheralRegister> regOpt = HardwareCryptoCatalog
                        .findRegisterByAddress(access.targetAddress());
                if (regOpt.isPresent()) {
                    HardwarePeripheralRegister reg = regOpt.get();
                    if (reg.feature() == HardwareCryptoFeature.TRNG_PERIPHERAL) {
                        findings.add(new CryptoFinding(
                                "HW-TRNG-" + Long.toHexString(access.instructionAddress()),
                                access.instructionAddress(),
                                4,
                                CryptoCategory.RANDOM_GENERATOR,
                                CryptoAlgorithm.TRNG,
                                CryptoConfidence.LIKELY,
                                Set.of(CryptoEvidenceLayer.HARDWARE_PERIPHERAL, CryptoEvidenceLayer.DATA_FLOW),
                                "Read from hardware TRNG random data register: " + reg.peripheralName(),
                                Long.toHexString(access.targetAddress()),
                                false,
                                Map.of("peripheral", reg.peripheralName(), "role", "CALLER_USE_SITE")
                        ));
                        detections++;
                    }
                }
                continue;
            }

            writesByTarget.put(access.targetAddress(), access.value());

            Optional<HardwarePeripheralRegister> regOpt = HardwareCryptoCatalog
                    .findRegisterByAddress(access.targetAddress());
            if (regOpt.isEmpty()) {
                continue;
            }

            HardwarePeripheralRegister reg = regOpt.get();

            if (reg.triggerRegister()) {
                // Corroborate write with mode and configuration registers
                CryptoConfidence confidence = CryptoConfidence.PLAUSIBLE;
                Set<CryptoEvidenceLayer> layers = new HashSet<>();
                layers.add(CryptoEvidenceLayer.HARDWARE_PERIPHERAL);

                String modeExplanation = reg.description();
                String rawMode = "";

                if (access.value().isPresent()) {
                    long val = access.value().getAsLong();
                    rawMode = "0x" + Long.toHexString(val);
                    if (reg.modeMapping().containsKey(val)) {
                        modeExplanation += " [Mode: " + reg.modeMapping().get(val) + "]";
                        confidence = CryptoConfidence.CONFIRMED;
                        layers.add(CryptoEvidenceLayer.DATA_FLOW);
                    } else if (val == 1) {
                        // Operation triggered
                        confidence = CryptoConfidence.LIKELY;
                        layers.add(CryptoEvidenceLayer.DATA_FLOW);
                    }
                }

                findings.add(new CryptoFinding(
                        "HW-PERIPH-" + Long.toHexString(access.instructionAddress()),
                        access.instructionAddress(),
                        reg.sizeBytes(),
                        reg.algorithm().defaultCategory(),
                        reg.algorithm(),
                        confidence,
                        layers,
                        modeExplanation,
                        rawMode.isEmpty() ? Long.toHexString(access.targetAddress()) : rawMode,
                        false,
                        Map.of(
                                "peripheral", reg.peripheralName(),
                                "registerId", reg.registerId(),
                                "role", "ALGORITHM_IMPLEMENTATION"
                        )
                ));
                detections++;
            }
        }

        return detections;
    }

    private int analyzeCallSites(
            List<HardwareCallSite> calls,
            List<CryptoFinding> findings,
            ParserLimits limits,
            CancellationToken token) throws DiagnosticException {

        int detections = 0;

        for (HardwareCallSite call : calls) {
            token.throwIfCancellationRequested();

            Optional<VendorRomCryptoRoutine> routineOpt = HardwareCryptoCatalog.findRomByName(call.targetName());
            if (routineOpt.isPresent()) {
                VendorRomCryptoRoutine routine = routineOpt.get();
                findings.add(new CryptoFinding(
                        "ROM-CALL-" + Long.toHexString(call.callAddress()),
                        call.callAddress(),
                        4,
                        routine.algorithm().defaultCategory(),
                        routine.algorithm(),
                        CryptoConfidence.CONFIRMED,
                        Set.of(CryptoEvidenceLayer.ROM_API, CryptoEvidenceLayer.SYMBOL_STRING),
                        "Call to resolved vendor ROM routine: " + routine.routineName()
                                + " (" + routine.description() + ")",
                        call.targetName(),
                        false,
                        Map.of(
                                "rom.routineId", routine.routineId(),
                                "rom.name", routine.routineName(),
                                "role", "WRAPPER"
                        )
                ));
                detections++;
                continue;
            }

            // Check if argument constants match 2-character RP2040 lookup codes (e.g. 'R' | ('E' << 8))
            for (Long arg : call.argumentConstants()) {
                if (arg != null && arg > 0 && arg <= 0xFFFF) {
                    char c1 = (char) (arg & 0xFF);
                    char c2 = (char) ((arg >> 8) & 0xFF);
                    String code = "" + c1 + c2;
                    Optional<VendorRomCryptoRoutine> codeOpt = HardwareCryptoCatalog.findRomByLookupCode(code);
                    if (codeOpt.isPresent()) {
                        VendorRomCryptoRoutine routine = codeOpt.get();
                        findings.add(new CryptoFinding(
                                "ROM-LOOKUP-" + Long.toHexString(call.callAddress()),
                                call.callAddress(),
                                4,
                                routine.algorithm().defaultCategory(),
                                routine.algorithm(),
                                CryptoConfidence.CONFIRMED,
                                Set.of(CryptoEvidenceLayer.ROM_API, CryptoEvidenceLayer.DATA_FLOW),
                                "RP2040 ROM lookup code '" + code + "': " + routine.routineName(),
                                code,
                                false,
                                Map.of(
                                        "rom.routineId", routine.routineId(),
                                        "rom.lookupCode", code,
                                        "role", "CALLER_USE_SITE"
                                )
                        ));
                        detections++;
                    }
                }
            }
        }

        return detections;
    }

    private int analyzeSecureElements(
            List<HardwareCallSite> calls,
            List<HardwareMemoryAccess> accesses,
            List<CryptoFinding> findings,
            ParserLimits limits,
            CancellationToken token) throws DiagnosticException {

        int detections = 0;

        for (HardwareCallSite call : calls) {
            token.throwIfCancellationRequested();
            String nameLower = call.targetName().toLowerCase(java.util.Locale.ROOT);

            for (SecureElementDefinition se : HardwareCryptoCatalog.secureElements()) {
                String idLower = se.elementId().toLowerCase(java.util.Locale.ROOT);
                if (nameLower.contains(idLower) || nameLower.contains("atecc") || nameLower.contains("optiga")) {
                    findings.add(new CryptoFinding(
                            "SEC-ELEM-" + Long.toHexString(call.callAddress()),
                            call.callAddress(),
                            4,
                            CryptoCategory.HARDWARE_SECURITY,
                            CryptoAlgorithm.SECURE_ELEMENT,
                            CryptoConfidence.CONFIRMED,
                            Set.of(CryptoEvidenceLayer.HARDWARE_PERIPHERAL, CryptoEvidenceLayer.SYMBOL_STRING),
                            "Interface to secure element " + se.elementId()
                                    + " (" + se.manufacturer() + " " + se.model() + ")",
                            se.elementId(),
                            false,
                            Map.of(
                                    "secureElement.id", se.elementId(),
                                    "secureElement.manufacturer", se.manufacturer(),
                                    "role", "WRAPPER"
                            )
                    ));
                    detections++;
                    break;
                }
            }
        }

        return detections;
    }

    private int analyzeCrossProgramReferences(
            List<CrossProgramCryptoReference> crossRefs,
            List<CryptoFinding> findings,
            ParserLimits limits,
            CancellationToken token) throws DiagnosticException {

        int detections = 0;

        for (CrossProgramCryptoReference ref : crossRefs) {
            token.throwIfCancellationRequested();

            findings.add(new CryptoFinding(
                    "CROSS-PROG-" + ref.referenceId(),
                    ref.sharedAddress(),
                    ref.lengthBytes(),
                    CryptoCategory.HARDWARE_SECURITY,
                    CryptoAlgorithm.EFUSE_KEY_LADDER,
                    ref.verified() ? CryptoConfidence.CONFIRMED : CryptoConfidence.LIKELY,
                    Set.of(CryptoEvidenceLayer.DATA_FLOW, CryptoEvidenceLayer.HARDWARE_CONFIG),
                    "Cross-program crypto handoff from " + ref.sourceProgram() + " to "
                            + ref.targetProgram() + " (" + ref.purpose() + ")",
                    ref.referenceId(),
                    false,
                    Map.of(
                            "crossProgram.source", ref.sourceProgram(),
                            "crossProgram.target", ref.targetProgram(),
                            "crossProgram.purpose", ref.purpose(),
                            "role", "KEY_SCHEDULE"
                    )
            ));
            detections++;
        }

        return detections;
    }
}
