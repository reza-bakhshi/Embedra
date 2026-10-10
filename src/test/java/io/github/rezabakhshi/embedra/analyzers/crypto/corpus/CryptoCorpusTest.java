package io.github.rezabakhshi.embedra.analyzers.crypto.corpus;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.analyzers.crypto.hardware.HardwareCryptoPlatform;
import io.github.rezabakhshi.embedra.analyzers.crypto.signatures.CryptoIsa;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class CryptoCorpusTest {

    private CryptoCorpus corpus;

    @BeforeEach
    void setUp() {
        corpus = CryptoCorpus.defaultCorpus();
    }

    @Test
    void verifiesCorpusSampleCountsAndClassifications() {
        List<CryptoCorpusSample> all = corpus.allSamples();
        assertEquals(31, all.size(), "Corpus must contain exactly 31 deterministic samples");

        List<CryptoCorpusSample> positive = corpus.positiveSamples();
        assertEquals(12, positive.size(), "Positive corpus must contain 12 samples across target ISAs");

        List<CryptoCorpusSample> negative = corpus.negativeSamples();
        assertEquals(15, negative.size(), "Negative adversarial corpus must contain 15 samples");

        List<CryptoCorpusSample> unsupported = corpus.unsupportedSamples();
        assertEquals(4, unsupported.size(), "Corpus must contain 4 explicit unsupported variants");
    }

    @Test
    void coversAllTargetSiliconPlatformsAndIsas() {
        Set<HardwareCryptoPlatform> platforms = new HashSet<>();
        Set<CryptoIsa> isas = new HashSet<>();

        for (CryptoCorpusSample sample : corpus.positiveSamples()) {
            platforms.add(sample.platform());
            isas.add(sample.isa());
        }

        // ESP targets: ESP32, ESP32_S3, ESP32_C3, ESP32_C6
        assertTrue(platforms.contains(HardwareCryptoPlatform.ESP32));
        assertTrue(platforms.contains(HardwareCryptoPlatform.ESP32_S3));
        assertTrue(platforms.contains(HardwareCryptoPlatform.ESP32_C3));
        assertTrue(platforms.contains(HardwareCryptoPlatform.ESP32_C6));

        // STM32 targets: STM32F4, STM32F7, STM32H7, STM32L4, STM32WB
        assertTrue(platforms.contains(HardwareCryptoPlatform.STM32_F4));
        assertTrue(platforms.contains(HardwareCryptoPlatform.STM32_F7));
        assertTrue(platforms.contains(HardwareCryptoPlatform.STM32_H7));
        assertTrue(platforms.contains(HardwareCryptoPlatform.STM32_L4));
        assertTrue(platforms.contains(HardwareCryptoPlatform.STM32_WB));

        // RP targets: RP2040, RP2350
        assertTrue(platforms.contains(HardwareCryptoPlatform.RP2040));
        assertTrue(platforms.contains(HardwareCryptoPlatform.RP2350));

        // Target ISAs: Xtensa, ARM Thumb, RISC-V 32
        assertTrue(isas.contains(CryptoIsa.XTENSA));
        assertTrue(isas.contains(CryptoIsa.ARM_THUMB));
        assertTrue(isas.contains(CryptoIsa.RISCV32));
    }

    @Test
    void enforcesSampleMetadataIntegrityAndImmutability() {
        Set<String> ids = new HashSet<>();

        for (CryptoCorpusSample sample : corpus.allSamples()) {
            assertNotNull(sample.id());
            assertFalse(sample.id().isBlank());
            assertTrue(ids.add(sample.id()), "Duplicate sample ID detected: " + sample.id());

            assertNotNull(sample.title());
            assertFalse(sample.title().isBlank());

            assertNotNull(sample.toolchain());
            assertFalse(sample.toolchain().isBlank());

            assertNotNull(sample.payload());
            assertTrue(sample.payload().length > 0, "Payload must not be empty for " + sample.id());

            assertNotNull(sample.description());

            // Defensive copy verification
            byte[] copy = sample.payload();
            byte originalByte = copy[0];
            copy[0] = (byte) (originalByte ^ 0xFF);
            assertEquals(originalByte, sample.payload()[0], "Payload must be defensively copied");
        }
    }

    @Test
    void validatesExplicitUnsupportedCases() {
        List<CryptoCorpusSample> unsupported = corpus.unsupportedSamples();
        for (CryptoCorpusSample sample : unsupported) {
            assertTrue(sample.optionalUnsupportedCase().isPresent());
            UnsupportedCase uc = sample.optionalUnsupportedCase().get();
            assertEquals(sample.id(), uc.sampleId());
            assertNotNull(uc.targetAlgorithm());
            assertNotNull(uc.reason());
            assertFalse(uc.description().isBlank());
            assertFalse(uc.plannedMitigation().isBlank());
        }
    }
}
