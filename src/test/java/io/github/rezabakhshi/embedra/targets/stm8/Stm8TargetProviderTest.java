package io.github.rezabakhshi.embedra.targets.stm8;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.catalog.SupportState;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.core.model.Confidence;
import io.github.rezabakhshi.embedra.core.model.ExecutionTopology;
import io.github.rezabakhshi.embedra.core.model.ProcessorNode;
import io.github.rezabakhshi.embedra.targets.EntryPointDecision;
import io.github.rezabakhshi.embedra.targets.LanguageSelection;
import io.github.rezabakhshi.embedra.targets.SupportDecision;
import io.github.rezabakhshi.embedra.targets.stm8.catalog.Stm8CatalogRegistry;
import io.github.rezabakhshi.embedra.targets.stm8.catalog.Stm8PartRecord;
import io.github.rezabakhshi.embedra.targets.stm8.memory.Stm8MemoryPlan;
import io.github.rezabakhshi.embedra.targets.stm8.memory.Stm8MemoryPlanner;
import io.github.rezabakhshi.embedra.targets.stm8.memory.Stm8MemoryRegion;
import io.github.rezabakhshi.embedra.targets.stm8.memory.Stm8MemoryRegionKind;
import java.io.IOException;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Unit test suite for pure STM8 target providers, exact-part catalog registry, and memory planners.
 */
class Stm8TargetProviderTest {

    private static Stm8CatalogRegistry registry;

    @BeforeAll
    static void setUp() throws Exception {
        registry = Stm8CatalogRegistry.loadDefault();
    }

    @Test
    void catalogRegistryLoadsThirtyTwoExactSiliconParts() {
        assertEquals(32, registry.partCount(), "Catalog must contain exactly 32 curated parts");
        assertEquals(32, registry.listParts().size());

        List<Stm8PartRecord> stm8sParts = registry.listPartsByFamily("STM8S");
        assertFalse(stm8sParts.isEmpty());

        List<Stm8PartRecord> stm8lParts = registry.listPartsByFamily("STM8L");
        assertFalse(stm8lParts.isEmpty());


        List<Stm8PartRecord> stm8aParts = registry.listPartsByFamily("STM8A");
        assertFalse(stm8aParts.isEmpty());

        List<Stm8PartRecord> stm8tParts = registry.listPartsByFamily("STM8T");
        assertFalse(stm8tParts.isEmpty());
    }

    @Test
    void catalogRegistryEnforcesExactPartMatchingAndRejectsWildcards() throws DiagnosticException {
        // Exact lookups
        Optional<Stm8PartRecord> s003 = registry.findPart("STM8S003F3P6");
        assertTrue(s003.isPresent());
        assertEquals("STM8S", s003.get().family());
        assertEquals(8192L, s003.get().flashBytes());
        assertEquals(1024L, s003.get().ramBytes());
        assertEquals(128L, s003.get().eepromBytes());
        assertEquals(SupportState.SUPPORTED, s003.get().supportState());
        Optional<Stm8PartRecord> s003k3 = registry.findPart("STM8S003K3T6C");
        assertTrue(s003k3.isPresent());
        assertEquals(SupportState.PLANNED, s003k3.get().supportState());

        // Case insensitivity
        assertTrue(registry.findPart("stm8s003f3p6").isPresent());

        // Rejection of wildcards, regex, and fuzzy matching per STM8-007
        assertTrue(registry.findPart("STM8S*").isEmpty());
        assertTrue(registry.findPart("STM8S?").isEmpty());
        assertTrue(registry.findPart("STM8S").isEmpty());
        assertTrue(registry.findPart("STM8S003").isEmpty());
        assertTrue(registry.findPart("").isEmpty());
        assertTrue(registry.findPart(null).isEmpty());

        // Fail-closed getRequiredPart
        assertNotNull(registry.getRequiredPart("STM8S208RBT6"));
        DiagnosticException ex = assertThrows(
            DiagnosticException.class,
            () -> registry.getRequiredPart("NON_EXISTENT_PART")
        );
        assertEquals(DiagnosticCode.STM8_TARGET_UNSUPPORTED, ex.diagnostic().code());
    }

    @Test
    void targetProvidersCoverAllFourFamilies() throws DiagnosticException {
        assertEquals(4, Stm8TargetProviders.all().size());

        Stm8TargetProvider stm8s = Stm8TargetProviders.getRequiredProvider("STM8S");
        assertEquals("STM8S", stm8s.family());

        Stm8TargetProvider stm8l = Stm8TargetProviders.getRequiredProvider("STM8L");
        assertEquals("STM8L", stm8l.family());

        Stm8TargetProvider stm8a = Stm8TargetProviders.getRequiredProvider("STM8A");
        assertEquals("STM8A", stm8a.family());

        Stm8TargetProvider stm8t = Stm8TargetProviders.getRequiredProvider("STM8T");
        assertEquals("STM8T", stm8t.family());

        DiagnosticException ex = assertThrows(
            DiagnosticException.class,
            () -> Stm8TargetProviders.getRequiredProvider("UNKNOWN_FAMILY")
        );
        assertEquals(DiagnosticCode.STM8_TARGET_UNSUPPORTED, ex.diagnostic().code());
    }

    @Test
    void providerSupportsAndRejectsAppropriateParts() throws DiagnosticException {
        Stm8TargetProvider stm8s = Stm8TargetProviders.getRequiredProvider("STM8S");
        Stm8PartRecord sPart = registry.getRequiredPart("STM8S003F3P6");
        Stm8PartRecord lPart = registry.getRequiredPart("STM8L151C8T6");

        SupportDecision sDec = stm8s.supports(sPart);
        assertTrue(sDec.supported());
        assertTrue(sDec.deviceId().isPresent());

        SupportDecision lDec = stm8s.supports(lPart);
        assertFalse(lDec.supported());
        assertTrue(lDec.deviceId().isEmpty());

        Optional<Stm8TargetProvider> resolved = Stm8TargetProviders.forPart(sPart);
        assertTrue(resolved.isPresent());
        assertEquals("STM8S", resolved.get().family());
    }

    @Test
    void memoryPlanningProducesConformingAndNonOverlappingLayouts() throws DiagnosticException {
        Stm8TargetProvider stm8s = Stm8TargetProviders.getRequiredProvider("STM8S");
        Stm8PartRecord part = registry.getRequiredPart("STM8S003F3P6");

        Stm8MemoryPlan plan = stm8s.planMemory(part, ParserLimits.defaults(), CancellationToken.none());
        assertNotNull(plan);
        assertEquals(part, plan.part());

        // Validate RAM region
        Optional<Stm8MemoryRegion> ram = plan.findRegionByName("RAM");
        assertTrue(ram.isPresent());
        assertEquals(Stm8MemoryRegionKind.RAM, ram.get().kind());
        assertEquals(0x000000L, ram.get().startAddress());
        assertEquals(1024L, ram.get().sizeBytes());
        assertTrue(ram.get().readable());
        assertTrue(ram.get().writable());
        assertFalse(ram.get().executable());

        // Validate EEPROM region
        Optional<Stm8MemoryRegion> eeprom = plan.findRegionByName("DATA_EEPROM");
        assertTrue(eeprom.isPresent());
        assertEquals(0x004000L, eeprom.get().startAddress());
        assertEquals(128L, eeprom.get().sizeBytes());

        // Validate Option Bytes
        Optional<Stm8MemoryRegion> opt = plan.findRegionByName("OPTION_BYTES");
        assertTrue(opt.isPresent());
        assertEquals(0x004800L, opt.get().startAddress());
        assertEquals(128L, opt.get().sizeBytes());

        // Validate Peripherals
        Optional<Stm8MemoryRegion> periph = plan.findRegionByName("PERIPHERALS");
        assertTrue(periph.isPresent());
        assertEquals(0x005000L, periph.get().startAddress());
        assertEquals(2048L, periph.get().sizeBytes());

        // Validate Boot ROM
        Optional<Stm8MemoryRegion> rom = plan.findRegionByName("BOOT_ROM");
        assertTrue(rom.isPresent());
        assertEquals(0x006000L, rom.get().startAddress());
        assertEquals(2048L, rom.get().sizeBytes());
        assertTrue(rom.get().executable());

        // Validate Flash
        Optional<Stm8MemoryRegion> flash = plan.findRegionByName("FLASH");
        assertTrue(flash.isPresent());
        assertEquals(0x008000L, flash.get().startAddress());
        assertEquals(8192L, flash.get().sizeBytes());
        assertTrue(flash.get().executable());

        // Mapping checks
        assertTrue(plan.isMapped(0x000100L));
        assertTrue(plan.isMapped(0x004010L));
        assertTrue(plan.isMapped(0x005050L));
        assertTrue(plan.isMapped(0x008080L));
        assertFalse(plan.isMapped(0x003FFFL)); // Unmapped hole between RAM and EEPROM
        assertFalse(plan.isMapped(0x030000L)); // Beyond 8K flash
    }

    @Test
    void languageSelectionAdaptsToFlashAddressWidth() throws DiagnosticException {
        Stm8TargetProvider stm8s = Stm8TargetProviders.getRequiredProvider("STM8S");

        // Small part (8 KiB Flash -> 16-bit addressing)
        Stm8PartRecord smallPart = registry.getRequiredPart("STM8S003F3P6");
        LanguageSelection smallLang = stm8s.selectLanguage(smallPart);
        assertEquals("STM8:default:16:default", smallLang.languageId());
        assertEquals(16, smallLang.addressSizeBits());
        assertEquals("BIG_ENDIAN", smallLang.endianness());

        // Large part (128 KiB Flash -> 24-bit addressing)
        Stm8PartRecord largePart = registry.getRequiredPart("STM8S208RBT6");
        LanguageSelection largeLang = stm8s.selectLanguage(largePart);
        assertEquals("STM8:default:24:default", largeLang.languageId());
        assertEquals(24, largeLang.addressSizeBits());
    }

    @Test
    void executionTopologyModelsSingleCoreProcessor() throws DiagnosticException {
        Stm8TargetProvider stm8s = Stm8TargetProviders.getRequiredProvider("STM8S");
        Stm8PartRecord part = registry.getRequiredPart("STM8S003F3P6");

        ExecutionTopology topology = stm8s.buildTopology(part);
        assertNotNull(topology);
        assertEquals(1, topology.processors().size());

        ProcessorNode core = topology.processors().get(0);
        assertEquals("STM8S003F3P6.core0", core.id());
        assertTrue(core.instructionSet().isPresent());
        assertEquals("STM8", core.instructionSet().get());
        assertEquals(Confidence.VERIFIED, core.confidence());
        assertEquals(1, core.resetEntries().size());
        assertEquals(0x008000L, core.resetEntries().get(0).address());
    }

    @Test
    void entryPointValidationDistinguishesExecutableAndNonExecutableRegions() throws DiagnosticException {
        Stm8TargetProvider stm8s = Stm8TargetProviders.getRequiredProvider("STM8S");
        Stm8PartRecord part = registry.getRequiredPart("STM8S003F3P6");

        // Flash is executable
        EntryPointDecision validDecision = stm8s.validateEntry(0x008080L, part);
        assertTrue(validDecision.accepted());
        assertTrue(validDecision.classification().isPresent());

        // RAM is non-executable
        EntryPointDecision ramDecision = stm8s.validateEntry(0x000100L, part);
        assertFalse(ramDecision.accepted());

        // Outside memory
        EntryPointDecision outsideDecision = stm8s.validateEntry(0x050000L, part);
        assertFalse(outsideDecision.accepted());
    }

    @Test
    void cancellationTokenAndLimitsAreEnforced() throws DiagnosticException {
        Stm8TargetProvider stm8s = Stm8TargetProviders.getRequiredProvider("STM8S");
        Stm8PartRecord part = registry.getRequiredPart("STM8S003F3P6");

        CancellationToken cancelledToken = () -> true;
        DiagnosticException ex = assertThrows(
            DiagnosticException.class,
            () -> stm8s.planMemory(part, ParserLimits.defaults(), cancelledToken)
        );
        assertEquals(DiagnosticCode.CANCELLED, ex.diagnostic().code());

        ParserLimits tightLimits = ParserLimits.defaults().withMaxAllocationBytes(1024L);
        DiagnosticException limitEx = assertThrows(
            DiagnosticException.class,
            () -> stm8s.planMemory(part, tightLimits, CancellationToken.none())
        );
        assertEquals(DiagnosticCode.LIMIT_EXCEEDED, limitEx.diagnostic().code());
    }

    @Test
    void stm8ClassesAreStrictlyIsolatedFromStm32CortexM() {
        // Enforces STM8-001: No STM32 layout, Thumb instruction, Cortex-M exception model,
        // SVD pack, or vector assumptions
        Class<?>[] stm8Classes = {

            Stm8TargetProvider.class,
            AbstractStm8TargetProvider.class,
            Stm8sTargetProvider.class,
            Stm8lTargetProvider.class,
            Stm8aTargetProvider.class,
            Stm8tTargetProvider.class,
            Stm8TargetProviders.class,
            Stm8PartRecord.class,
            Stm8CatalogRegistry.class,
            Stm8MemoryRegion.class,
            Stm8MemoryPlan.class,
            Stm8MemoryPlanner.class
        };

        for (Class<?> clazz : stm8Classes) {
            assertFalse(
                clazz.getName().contains("stm32"),
                "STM8 class must not be under stm32 package: " + clazz.getName()
            );

            for (Method m : clazz.getDeclaredMethods()) {
                assertFalse(
                    m.getReturnType().getName().contains("stm32"),
                    "Return type must not reference STM32: " + m.getReturnType().getName()
                );
            }
        }
    }
}
