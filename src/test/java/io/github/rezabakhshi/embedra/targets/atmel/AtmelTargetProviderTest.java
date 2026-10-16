package io.github.rezabakhshi.embedra.targets.atmel;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.model.ExecutionTopology;
import io.github.rezabakhshi.embedra.targets.EntryPointDecision;
import io.github.rezabakhshi.embedra.targets.LanguageSelection;
import io.github.rezabakhshi.embedra.targets.SupportDecision;
import io.github.rezabakhshi.embedra.targets.atmel.catalog.AtmelPartRecord;
import java.util.Optional;
import org.junit.jupiter.api.Test;

/**
 * Automated tests for Atmel target providers and registry resolution.
 */
class AtmelTargetProviderTest {

    @Test
    void providersSupportExpectedSeries() {
        AtmelTargetProvider megaProvider = new AtmegaTargetProvider();
        AtmelTargetProvider tinyProvider = new AttinyTargetProvider();
        AtmelTargetProvider dxProvider = new AvrDxTargetProvider();
        AtmelTargetProvider samdProvider = new SamdTargetProvider();
        AtmelTargetProvider sameProvider = new SameTargetProvider();

        AtmelPartRecord m328 = AtmelPartRecord.defaultAtmega328p();
        AtmelPartRecord t85 = AtmelPartRecord.defaultAttiny85();
        AtmelPartRecord da48 = AtmelPartRecord.defaultAvr128da48();
        AtmelPartRecord samd = AtmelPartRecord.defaultSamd21g18a();
        AtmelPartRecord same = AtmelPartRecord.defaultSame70q21();

        // ATmega provider
        assertTrue(megaProvider.supports(m328).supported());
        assertFalse(megaProvider.supports(t85).supported());
        assertFalse(megaProvider.supports(samd).supported());

        // ATtiny provider
        assertTrue(tinyProvider.supports(t85).supported());
        assertFalse(tinyProvider.supports(m328).supported());

        // AVR-Dx provider
        assertTrue(dxProvider.supports(da48).supported());
        assertFalse(dxProvider.supports(m328).supported());

        // SAMD provider
        assertTrue(samdProvider.supports(samd).supported());
        assertFalse(samdProvider.supports(same).supported());

        // SAME provider
        assertTrue(sameProvider.supports(same).supported());
        assertFalse(sameProvider.supports(samd).supported());
    }

    @Test
    void targetProvidersRegistryResolution() {
        assertEquals(5, AtmelTargetProviders.all().size());

        assertTrue(AtmelTargetProviders.findById("atmel-atmega").isPresent());
        assertTrue(AtmelTargetProviders.findBySeries("SAMD").isPresent());

        Optional<AtmelTargetProvider> found = AtmelTargetProviders.findForPart(AtmelPartRecord.defaultAtmega328p());
        assertTrue(found.isPresent());
        assertEquals("atmel-atmega", found.get().providerId());
    }

    @Test
    void languageSelectionPerArchitecture() {
        AtmelTargetProvider mega = new AtmegaTargetProvider();
        LanguageSelection sel1 = mega.selectLanguage(AtmelPartRecord.defaultAtmega328p());
        assertEquals("avr8:LE:16:default", sel1.languageId());
        assertEquals("AVR8", sel1.instructionSet());

        LanguageSelection sel2 = mega.selectLanguage(AtmelPartRecord.defaultAtmega2560());
        assertEquals("avr8:LE:24:default", sel2.languageId());

        AtmelTargetProvider dx = new AvrDxTargetProvider();
        LanguageSelection sel3 = dx.selectLanguage(AtmelPartRecord.defaultAvr128da48());
        assertEquals("avr8:LE:24:xmega", sel3.languageId());
        assertEquals("AVR8X", sel3.instructionSet());

        AtmelTargetProvider samd = new SamdTargetProvider();
        LanguageSelection sel4 = samd.selectLanguage(AtmelPartRecord.defaultSamd21g18a());
        assertEquals("ARM:LE:32:v6M", sel4.languageId());
        assertEquals("ARMv6-M", sel4.instructionSet());

        AtmelTargetProvider same = new SameTargetProvider();
        LanguageSelection sel5 = same.selectLanguage(AtmelPartRecord.defaultSame70q21());
        assertEquals("ARM:LE:32:v7EM", sel5.languageId());
    }

    @Test
    void entryPointValidationRules() {
        AtmelTargetProvider mega = new AtmegaTargetProvider();
        AtmelPartRecord m328 = AtmelPartRecord.defaultAtmega328p();

        // AVR: 0x0000 is valid aligned address
        EntryPointDecision dec1 = mega.validateEntry(0x0000L, m328);
        assertTrue(dec1.accepted());

        // AVR: odd address 0x0001 is invalid (unaligned)
        EntryPointDecision dec2 = mega.validateEntry(0x0001L, m328);
        assertFalse(dec2.accepted());
        assertTrue(dec2.reason().contains("aligned"));

        // AVR: address outside flash is invalid
        EntryPointDecision dec3 = mega.validateEntry(0x10000L, m328);
        assertFalse(dec3.accepted());

        // SAM: 0x000000C1 has Thumb bit set and is in flash -> valid
        AtmelTargetProvider samd = new SamdTargetProvider();
        AtmelPartRecord samdPart = AtmelPartRecord.defaultSamd21g18a();
        EntryPointDecision dec4 = samd.validateEntry(0x000000C1L, samdPart);
        assertTrue(dec4.accepted());

        // SAM: 0x000000C0 missing Thumb bit -> invalid
        EntryPointDecision dec5 = samd.validateEntry(0x000000C0L, samdPart);
        assertFalse(dec5.accepted());
        assertTrue(dec5.reason().contains("Thumb"));
    }

    @Test
    void executionTopologyGeneration() {
        AtmelTargetProvider mega = new AtmegaTargetProvider();
        ExecutionTopology topo = mega.buildTopology(AtmelPartRecord.defaultAtmega328p());

        assertNotNull(topo);
        assertEquals(1, topo.processors().size());
        assertEquals("ATmega328P.core0", topo.processors().getFirst().id());
        assertEquals("AVR RISC", topo.processors().getFirst().instructionSet().orElseThrow());
    }
}
