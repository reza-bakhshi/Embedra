package io.github.rezabakhshi.embedra.ghidra.stm32;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ghidra.GhidraApplicationLayout;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.app.util.opinion.IntelHexLoader;
import ghidra.app.util.opinion.LoadResults;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.Loader;
import ghidra.app.util.opinion.Loader.ImporterSettings;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.model.listing.Program;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.lang.LanguageID;
import ghidra.util.task.TaskMonitor;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.stm32.input.Stm32AddressedInput;
import io.github.rezabakhshi.embedra.core.stm32.input.Stm32ElfInput;
import io.github.rezabakhshi.embedra.core.stm32.input.Stm32IntelHexInput;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class Stm32AddressedInputInspectorTest {
    @BeforeAll
    static void initializeGhidra() throws Exception {
        if (!Application.isInitialized()) {
            ApplicationConfiguration configuration = new ApplicationConfiguration();
            configuration.setInitializeLogging(false);
            Application.initializeApplication(new GhidraApplicationLayout(
                new File(System.getenv("GHIDRA_INSTALL_DIR"))), configuration);
        }
    }

    @Test
    void elfAndAxfPreserveSegmentSectionAndThumbEntryAddresses() throws Exception {
        byte[] bytes = fixture("stm32f103", "STM32F103C8T6.elf");
        Stm32AddressedInput input = inspect("renamed.axf", bytes);
        Stm32ElfInput elf = assertInstanceOf(Stm32ElfInput.class, input);
        assertEquals(Stm32AddressedInput.Format.ELF, elf.format());
        assertEquals(0x08000101L, elf.encodedEntryPoint().orElseThrow());
        assertEquals(0x08000000L, elf.loadSegments().getFirst().virtualAddress());
        assertEquals(0x08000000L, elf.loadSegments().getFirst().physicalAddress());
        assertTrue(elf.sections().stream().anyMatch(section ->
            section.name().equals(".isr_vector") && section.encodedAddress() == 0x08000000L));
        assertTrue(elf.sections().stream().anyMatch(section ->
            section.name().equals(".text") && section.encodedAddress() == 0x08000100L));
        assertEquals(ElfLoader.class, Stm32AddressedInputInspector.nativeLoaderClass(input));
    }

    @Test
    void specialAddressesRemainEncodedAndDoNotIdentifyAnExactDevice() throws Exception {
        Stm32ElfInput n6 = assertInstanceOf(Stm32ElfInput.class,
            inspect("neutral.dat", fixture("stm32-core-samples", "STM32N657X0H3Q.elf")));
        assertEquals(0x34000000L, n6.loadSegments().getFirst().virtualAddress());
        assertEquals(0x34000101L, n6.encodedEntryPoint().orElseThrow());
        Stm32IntelHexInput wl3 = assertInstanceOf(Stm32IntelHexInput.class,
            inspect("neutral.dat", fixture("stm32-core-samples", "STM32WL33CCV6TR.hex")));
        assertEquals(0x10040000L, wl3.dataRecords().getFirst().encodedAddress());
        assertEquals(0x10040101L, wl3.encodedEntryPoint().orElseThrow());
        assertEquals(IntelHexLoader.class, Stm32AddressedInputInspector.nativeLoaderClass(wl3));
    }

    @Test
    void allTwentyFourGoldenPairsAgreeOnEncodedImageAndEntryAddresses() throws Exception {
        String[][] groups = {
            {"stm32f103", "STM32F103C8T6", "STM32F103CBT6", "STM32F103RBT6"},
            {"stm32c0", "STM32C051C8T6", "STM32C071RBT6", "STM32C092RCT6"},
            {"stm32-core-samples", "STM32F207ZGT6", "STM32F401RET6",
                "STM32F756ZGT6", "STM32G0B1RET6", "STM32G431RBT6", "STM32H503RBT6",
                "STM32H735IGK6", "STM32L412KBU3", "STM32L4P5CGU6", "STM32L562QEI6Q",
                "STM32N657X0H3Q", "STM32U031R8T6", "STM32U385RGT6Q",
                "STM32U545RET6Q", "STM32WB05KZV6TR", "STM32WB15CCU6",
                "STM32WBA25CEU7", "STM32WL33CCV6TR"}
        };
        int pairs = 0;
        for (String[] group : groups) {
            for (int index = 1; index < group.length; index++) {
                String name = group[index];
                Stm32ElfInput elf = assertInstanceOf(Stm32ElfInput.class,
                    inspect(name + ".elf", fixture(group[0], name + ".elf")));
                Stm32IntelHexInput hex = assertInstanceOf(Stm32IntelHexInput.class,
                    inspect(name + ".hex", fixture(group[0], name + ".hex")));
                assertEquals(elf.loadSegments().getFirst().virtualAddress(),
                    hex.dataRecords().getFirst().encodedAddress(), name);
                assertEquals(elf.encodedEntry(), hex.encodedEntryPoint().orElseThrow(), name);
                pairs++;
            }
        }
        assertEquals(24, pairs);
    }

    @Test
    void extendedSegmentRecordsUseEncodedBaseAndStartAddress() throws Exception {
        String hex = ":020000021200EA\n:01001000AA45\n:0400000312345678E5\n:00000001FF\n";
        Stm32IntelHexInput input = assertInstanceOf(Stm32IntelHexInput.class,
            inspect("segment.hex", hex.getBytes(StandardCharsets.US_ASCII)));
        assertEquals(0x12010L, input.dataRecords().getFirst().encodedAddress());
        assertEquals(0x179b8L, input.encodedEntryPoint().orElseThrow());
        assertEquals(2, input.dataRecords().getFirst().line());
    }

    @Test
    void malformedRecordsAndRawInputDoNotReceiveAnAddressModel() throws Exception {
        byte[] valid = fixture("stm32-core-samples", "STM32WL33CCV6TR.hex");
        String changed = new String(valid, StandardCharsets.US_ASCII)
            .replaceFirst(":10000000", ":10000001");
        assertThrows(IOException.class,
            () -> inspect("bad.hex", changed.getBytes(StandardCharsets.US_ASCII)));
        assertThrows(IOException.class, () -> inspect("truncated.axf", new byte[] {
            0x7f, 'E', 'L', 'F', 1, 1, 1
        }));
        assertThrows(IOException.class, () -> inspect("raw.bin", new byte[32]));
    }

    @Test
    void nativeGhidraLoadersMapEncodedAddresses() throws Exception {
        assertNativeMemory("stm32f103", "STM32F103C8T6.elf", 0x08000000L);
        assertNativeMemory("stm32-core-samples", "STM32WL33CCV6TR.hex", 0x10040000L);
    }

    private static void assertNativeMemory(String folder, String filename, long address)
            throws Exception {
        byte[] bytes = fixture(folder, filename);
        ByteArrayProvider provider = new ByteArrayProvider(filename, bytes);
        Stm32AddressedInput model = Stm32AddressedInputInspector.inspect(provider,
            ParserLimits.defaults(), CancellationToken.none());
        Loader loader = Stm32AddressedInputInspector.nativeLoaderClass(model)
            .getDeclaredConstructor().newInstance();
        assertFalse(loader.findSupportedLoadSpecs(provider).isEmpty());
        LoadSpec spec = new LoadSpec(loader, 0,
            new LanguageCompilerSpecPair(new LanguageID("ARM:LE:32:Cortex"),
                new CompilerSpecID("default")), false);
        ImporterSettings settings = new ImporterSettings(provider, filename, null, "/",
            false, spec, loader.getDefaultOptions(provider, spec, null, false, false),
            new Object(), new MessageLog(), TaskMonitor.DUMMY);
        try (LoadResults<?> results = loader.load(settings)) {
            Program[] captured = new Program[1];
            results.getPrimary().apply(domainObject -> captured[0] = (Program) domainObject);
            Program program = captured[0];
            assertNotNull(program);
            assertNotNull(program.getMemory().getBlock(
                program.getAddressFactory().getDefaultAddressSpace().getAddress(address)));
            assertFalse(program.getMemory().isEmpty());
        }
    }

    private static Stm32AddressedInput inspect(String filename, byte[] bytes)
            throws Exception {
        return Stm32AddressedInputInspector.inspect(new ByteArrayProvider(filename, bytes),
            ParserLimits.defaults(), CancellationToken.none());
    }

    private static byte[] fixture(String folder, String filename) throws IOException {
        String path = "/fixtures/" + folder + "/" + filename;
        try (InputStream input = Stm32AddressedInputInspectorTest.class.getResourceAsStream(path)) {
            assertNotNull(input, path);
            return input.readAllBytes();
        }
    }
}
