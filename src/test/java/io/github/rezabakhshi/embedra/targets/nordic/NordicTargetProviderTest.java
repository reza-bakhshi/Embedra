package io.github.rezabakhshi.embedra.targets.nordic;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.model.ExecutionTopology;
import io.github.rezabakhshi.embedra.targets.EntryPointDecision;
import io.github.rezabakhshi.embedra.targets.LanguageSelection;
import io.github.rezabakhshi.embedra.targets.SupportDecision;
import io.github.rezabakhshi.embedra.targets.nordic.catalog.NordicCatalogRegistry;
import io.github.rezabakhshi.embedra.targets.nordic.catalog.NordicPartRecord;
import io.github.rezabakhshi.embedra.targets.nordic.memory.NordicMemoryPlan;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for Nordic target providers (T098).
 */
class NordicTargetProviderTest {

    private NordicCatalogRegistry registry;

    @BeforeEach
    void setUp() throws Exception {
        registry = NordicCatalogRegistry.loadDefault();
    }

    @Test
    void allFiveProvidersAreRegisteredAndResolvable() {
        assertEquals(5, NordicTargetProviders.all().size());

        assertTrue(NordicTargetProviders.findById("nordic.nrf51").isPresent());
        assertTrue(NordicTargetProviders.findById("nordic.nrf52").isPresent());
        assertTrue(NordicTargetProviders.findById("nordic.nrf53").isPresent());
        assertTrue(NordicTargetProviders.findById("nordic.nrf54").isPresent());
        assertTrue(NordicTargetProviders.findById("nordic.nrf91").isPresent());

        assertTrue(NordicTargetProviders.findBySeries("nRF51").isPresent());
        assertTrue(NordicTargetProviders.findBySeries("nRF52").isPresent());
        assertTrue(NordicTargetProviders.findBySeries("nRF53").isPresent());
        assertTrue(NordicTargetProviders.findBySeries("nRF54").isPresent());
        assertTrue(NordicTargetProviders.findBySeries("nRF91").isPresent());
    }

    @Test
    void languageSelectionAssignsCorrectCortexMArchitectures() {
        NordicPartRecord nrf51 = registry.findExactPart("nRF51822-QFAA").orElseThrow();
        NordicTargetProvider provider51 = NordicTargetProviders.findForPart(nrf51).orElseThrow();
        LanguageSelection lang51 = provider51.selectLanguage(nrf51);
        assertEquals("ARM:LE:32:v6M", lang51.languageId());

        NordicPartRecord nrf52 = registry.findExactPart("nRF52832-QFAA").orElseThrow();
        NordicTargetProvider provider52 = NordicTargetProviders.findForPart(nrf52).orElseThrow();
        LanguageSelection lang52 = provider52.selectLanguage(nrf52);
        assertEquals("ARM:LE:32:v7EM", lang52.languageId());

        NordicPartRecord nrf53 = registry.findExactPart("nRF5340-QKAA").orElseThrow();
        NordicTargetProvider provider53 = NordicTargetProviders.findForPart(nrf53).orElseThrow();
        LanguageSelection lang53 = provider53.selectLanguage(nrf53);
        assertEquals("ARM:LE:32:v8M", lang53.languageId());

        NordicPartRecord nrf54 = registry.findExactPart("nRF54L15").orElseThrow();
        NordicTargetProvider provider54 = NordicTargetProviders.findForPart(nrf54).orElseThrow();
        LanguageSelection lang54 = provider54.selectLanguage(nrf54);
        assertEquals("ARM:LE:32:v8M", lang54.languageId());

        NordicPartRecord nrf91 = registry.findExactPart("nRF9160-SICA").orElseThrow();
        NordicTargetProvider provider91 = NordicTargetProviders.findForPart(nrf91).orElseThrow();
        LanguageSelection lang91 = provider91.selectLanguage(nrf91);
        assertEquals("ARM:LE:32:v8M", lang91.languageId());
    }

    @Test
    void supportsReturnsCorrectStateForCuratedParts() {
        NordicPartRecord part = registry.findExactPart("nRF52840-QIAA").orElseThrow();
        NordicTargetProvider provider = NordicTargetProviders.findForPart(part).orElseThrow();
        SupportDecision decision = provider.supports(part);
        assertTrue(decision.supported());
        assertEquals("nRF52840-QIAA", decision.deviceId().orElseThrow());
        assertEquals("SUPPORTED", part.supportState().name());

        NordicPartRecord plannedPart = registry.findExactPart("nRF52810-QCAA").orElseThrow();
        assertEquals("PLANNED", plannedPart.supportState().name());
    }

    @Test
    void memoryPlanningProducesValidPlansForRepresentativeParts() throws Exception {
        NordicPartRecord nrf52840 = registry.findExactPart("nRF52840-QIAA").orElseThrow();
        NordicTargetProvider provider = NordicTargetProviders.findForPart(nrf52840).orElseThrow();
        NordicMemoryPlan plan = provider.planMemory(nrf52840, ParserLimits.defaults(), CancellationToken.none());

        assertNotNull(plan);
        assertTrue(plan.isMapped(0x00000000L));
        assertTrue(plan.isExecutable(0x00000100L));
        assertTrue(plan.isMapped(0x20000000L));
        assertTrue(plan.isWritable(0x20000000L));
        assertTrue(plan.isMapped(0x10000000L)); // FICR
        assertTrue(plan.isMapped(0x10001000L)); // UICR
        assertTrue(plan.isMapped(0x5002A000L)); // CC310
    }

    @Test
    void dualCoreTopologyContainsTwoProcessorNodes() {
        NordicPartRecord nrf5340 = registry.findExactPart("nRF5340-QKAA").orElseThrow();
        NordicTargetProvider provider = NordicTargetProviders.findForPart(nrf5340).orElseThrow();
        ExecutionTopology topology = provider.buildTopology(nrf5340);

        assertNotNull(topology);
        assertEquals(2, topology.processors().size());
        assertEquals("nRF5340-QKAA.core0", topology.processors().get(0).id());
        assertEquals("nRF5340-QKAA.core1", topology.processors().get(1).id());
    }

    @Test
    void singleCoreTopologyContainsOneProcessorNode() {
        NordicPartRecord nrf52832 = registry.findExactPart("nRF52832-QFAA").orElseThrow();
        NordicTargetProvider provider = NordicTargetProviders.findForPart(nrf52832).orElseThrow();
        ExecutionTopology topology = provider.buildTopology(nrf52832);

        assertNotNull(topology);
        assertEquals(1, topology.processors().size());
        assertEquals("nRF52832-QFAA.core0", topology.processors().get(0).id());
    }

    @Test
    void entryPointValidationDistinguishesValidAndInvalidAddresses() {
        NordicPartRecord nrf52832 = registry.findExactPart("nRF52832-QFAA").orElseThrow();
        NordicTargetProvider provider = NordicTargetProviders.findForPart(nrf52832).orElseThrow();

        // Valid Thumb entry in Code Flash
        EntryPointDecision validDecision = provider.validateEntry(0x00000101L, nrf52832);
        assertTrue(validDecision.accepted());

        // Address outside Flash
        EntryPointDecision invalidDecision = provider.validateEntry(0x30000000L, nrf52832);
        assertFalse(invalidDecision.accepted());
    }
}
