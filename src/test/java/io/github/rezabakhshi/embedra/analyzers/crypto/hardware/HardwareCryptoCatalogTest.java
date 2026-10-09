package io.github.rezabakhshi.embedra.analyzers.crypto.hardware;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.analyzers.crypto.CryptoAlgorithm;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class HardwareCryptoCatalogTest {

    @Test
    void containsCatalogEntriesAcrossAllMajorPlatforms() {
        assertFalse(HardwareCryptoCatalog.registers().isEmpty());
        assertFalse(HardwareCryptoCatalog.romRoutines().isEmpty());
        assertFalse(HardwareCryptoCatalog.secureElements().isEmpty());

        // Check ESP32-S3 registers
        Optional<HardwarePeripheralRegister> espAes = HardwareCryptoCatalog.findRegisterByAddress(0x6003_a040L);
        assertTrue(espAes.isPresent());
        assertEquals(HardwareCryptoPlatform.ESP32_S3, espAes.get().platform());
        assertEquals("AES", espAes.get().peripheralName());
        assertFalse(espAes.get().triggerRegister());

        Optional<HardwarePeripheralRegister> espTrigger = HardwareCryptoCatalog.findRegisterByAddress(0x6003_a048L);
        assertTrue(espTrigger.isPresent());
        assertTrue(espTrigger.get().triggerRegister());

        // Check STM32 CRYP and HASH
        Optional<HardwarePeripheralRegister> stmCryp = HardwareCryptoCatalog.findRegisterByAddress(0x5006_0000L);
        assertTrue(stmCryp.isPresent());
        assertEquals("CRYP", stmCryp.get().peripheralName());

        Optional<HardwarePeripheralRegister> stmHash = HardwareCryptoCatalog.findRegisterByAddress(0x5006_0400L);
        assertTrue(stmHash.isPresent());
        assertEquals("HASH", stmHash.get().peripheralName());

        // Check RP2350
        Optional<HardwarePeripheralRegister> rpSha = HardwareCryptoCatalog.findRegisterByAddress(0x400d_0000L);
        assertTrue(rpSha.isPresent());
        assertEquals("SHA256", rpSha.get().peripheralName());

        Optional<HardwarePeripheralRegister> rpTrng = HardwareCryptoCatalog.findRegisterByAddress(0x400d_8000L);
        assertTrue(rpTrng.isPresent());
        assertEquals("TRNG", rpTrng.get().peripheralName());
    }

    @Test
    void resolvesVendorRomRoutinesByLookupCodeAndName() {
        Optional<VendorRomCryptoRoutine> re = HardwareCryptoCatalog.findRomByLookupCode("RE");
        assertTrue(re.isPresent());
        assertEquals("flash_range_erase", re.get().routineName());
        assertEquals(HardwareCryptoPlatform.RP2040, re.get().platform());

        Optional<VendorRomCryptoRoutine> espSha = HardwareCryptoCatalog.findRomByName("ets_sha256_process");
        assertTrue(espSha.isPresent());
        assertEquals(CryptoAlgorithm.SHA256, espSha.get().algorithm());
    }

    @Test
    void catalogsKnownSecureElements() {
        var ses = HardwareCryptoCatalog.secureElements();
        assertTrue(ses.stream().anyMatch(se -> se.elementId().equals("ATECC608A")));
        assertTrue(ses.stream().anyMatch(se -> se.elementId().equals("OPTIGA_TRUST_M")));
        assertTrue(ses.stream().anyMatch(se -> se.elementId().equals("SE050")));
    }
}
