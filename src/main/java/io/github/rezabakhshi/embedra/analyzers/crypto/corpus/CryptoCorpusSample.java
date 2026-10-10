package io.github.rezabakhshi.embedra.analyzers.crypto.corpus;

import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoAlgorithm;
import io.github.rezabakhshi.embedra.analyzers.crypto.hardware.CrossProgramCryptoReference;
import io.github.rezabakhshi.embedra.analyzers.crypto.hardware.HardwareCallSite;
import io.github.rezabakhshi.embedra.analyzers.crypto.hardware.HardwareCryptoPlatform;
import io.github.rezabakhshi.embedra.analyzers.crypto.hardware.HardwareMemoryAccess;
import io.github.rezabakhshi.embedra.analyzers.crypto.signatures.CryptoIsa;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Deterministic test case within the positive or negative cryptographic corpora (AN-003, AN-015).
 *
 * @param id unique identifier of the sample
 * @param title human-readable title describing the sample
 * @param classification positive, negative adversarial, or unsupported variant
 * @param platform target hardware silicon platform
 * @param isa target instruction set architecture
 * @param toolchain compiler, flags, and build environment
 * @param payload raw binary payload
 * @param baseAddress memory base address for analysis
 * @param stringLeads associated symbol or string leads
 * @param hardwareAccesses memory-mapped hardware peripheral accesses
 * @param callSites function and ROM API call sites
 * @param crossProgramRefs cross-program/core shared references
 * @param expectedAlgorithms cryptographic algorithms expected to be detected
 * @param expectedDetectors detectors expected to trigger on this sample
 * @param unsupportedCase explicit metadata if classification is UNSUPPORTED_VARIANT
 * @param description technical description of the sample
 */
public record CryptoCorpusSample(
        String id,
        String title,
        CryptoCorpusClassification classification,
        HardwareCryptoPlatform platform,
        CryptoIsa isa,
        String toolchain,
        byte[] payload,
        long baseAddress,
        List<String> stringLeads,
        List<HardwareMemoryAccess> hardwareAccesses,
        List<HardwareCallSite> callSites,
        List<CrossProgramCryptoReference> crossProgramRefs,
        Set<CryptoAlgorithm> expectedAlgorithms,
        Set<CryptoDetectorType> expectedDetectors,
        UnsupportedCase unsupportedCase,
        String description) {

    public CryptoCorpusSample {
        Objects.requireNonNull(id, "id must not be null");
        Objects.requireNonNull(title, "title must not be null");
        Objects.requireNonNull(classification, "classification must not be null");
        Objects.requireNonNull(platform, "platform must not be null");
        Objects.requireNonNull(isa, "isa must not be null");
        Objects.requireNonNull(toolchain, "toolchain must not be null");
        Objects.requireNonNull(payload, "payload must not be null");
        Objects.requireNonNull(description, "description must not be null");

        payload = payload.clone();
        stringLeads = stringLeads == null ? List.of() : List.copyOf(stringLeads);
        hardwareAccesses = hardwareAccesses == null ? List.of() : List.copyOf(hardwareAccesses);
        callSites = callSites == null ? List.of() : List.copyOf(callSites);
        crossProgramRefs = crossProgramRefs == null ? List.of() : List.copyOf(crossProgramRefs);
        expectedAlgorithms = expectedAlgorithms == null
                ? Set.of() : Collections.unmodifiableSet(Set.copyOf(expectedAlgorithms));
        expectedDetectors = expectedDetectors == null
                ? Set.of() : Collections.unmodifiableSet(Set.copyOf(expectedDetectors));
    }

    @Override
    public byte[] payload() {
        return payload.clone();
    }

    public Optional<UnsupportedCase> optionalUnsupportedCase() {
        return Optional.ofNullable(unsupportedCase);
    }
}
