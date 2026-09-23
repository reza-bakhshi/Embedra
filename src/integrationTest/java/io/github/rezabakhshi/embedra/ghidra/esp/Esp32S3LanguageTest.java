package io.github.rezabakhshi.embedra.ghidra.esp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ghidra.app.util.PseudoInstruction;
import ghidra.app.decompiler.DecompInterface;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.lang.ProcessorContextImpl;
import ghidra.program.model.lang.UnknownInstructionException;
import ghidra.program.model.mem.ByteMemBufferImpl;
import ghidra.program.model.address.AddressSet;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.util.DefaultLanguageService;
import java.io.File;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.Arrays;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import ghidra.util.task.TaskMonitor;

class Esp32S3LanguageTest {
    private static final byte[] SALT = {(byte) 0x50, (byte) 0x88, (byte) 0x72};

    @BeforeAll
    static void initializeGhidraApplication() throws Exception {
        if (!Application.isInitialized()) {
            String installDirectory = System.getenv("GHIDRA_INSTALL_DIR");
            ApplicationConfiguration configuration = new ApplicationConfiguration();
            configuration.setInitializeLogging(false);
            Application.initializeApplication(
                new GhidraApplicationLayout(new File(installDirectory)), configuration);
        }
    }

    @Test
    void genericXtensaCannotDecodeEsp32S3Salt() throws Exception {
        Language generic = DefaultLanguageService.getLanguageService().getLanguage(
            new LanguageID("Xtensa:LE:32:default"));
        var address = generic.getDefaultSpace().getAddress(0x420bdf4fL);
        var bytes = new ByteMemBufferImpl(address, SALT, false);

        assertThrows(UnknownInstructionException.class,
            () -> generic.parse(bytes, new ProcessorContextImpl(generic), false));
    }

    @Test
    void embedraEsp32S3LanguageDecodesSalt() throws Exception {
        Language language = DefaultLanguageService.getLanguageService().getLanguage(
            new LanguageID("Xtensa:LE:32:esp32s3"));
        var address = language.getDefaultSpace().getAddress(0x420bdf4fL);
        var bytes = new ByteMemBufferImpl(address, SALT, false);

        assertEquals(3, language.parse(bytes, new ProcessorContextImpl(language), false)
            .getLength());
    }

    @Test
    void assemblyOracleCoversOperandsFlowAndSignedness() throws Exception {
        Language language = DefaultLanguageService.getLanguageService().getLanguage(
            new LanguageID("Xtensa:LE:32:esp32s3"));
        byte[][] encodings = {
            {0x40, 0x23, 0x72}, {0x70, 0x56, 0x62},
            {0x50, (byte) 0x88, 0x72}, {(byte) 0x90, (byte) 0x88, 0x62}
        };
        String[] names = {"salt", "saltu", "salt", "saltu"};
        String[][] registers = {
            {"a2", "a3", "a4"}, {"a5", "a6", "a7"},
            {"a8", "a8", "a5"}, {"a8", "a8", "a9"}
        };
        byte[] fixture = fixtureCode();
        for (int index = 0; index < encodings.length; index++) {
            assertArrayEquals(encodings[index], Arrays.copyOfRange(fixture,
                index * 3, index * 3 + 3));
            var address = language.getDefaultSpace().getAddress(0x420bdf4fL + index * 3);
            var buffer = new ByteMemBufferImpl(address, encodings[index], false);
            var context = new ProcessorContextImpl(language);
            var prototype = language.parse(buffer, context, false);
            var instruction = new PseudoInstruction(address, prototype, buffer, context);
            assertEquals(3, instruction.getLength());
            assertEquals(names[index], instruction.getMnemonicString().toLowerCase());
            for (int operand = 0; operand < 3; operand++) {
                assertEquals(registers[index][operand],
                    instruction.getRegister(operand).getName());
            }
            assertEquals(address.add(3), instruction.getFallThrough());
            assertEquals(0, instruction.getFlows().length);
            int comparison = index % 2 == 0 ? PcodeOp.INT_SLESS : PcodeOp.INT_LESS;
            assertTrue(Arrays.stream(instruction.getPcode())
                .anyMatch(op -> op.getOpcode() == comparison));
        }
    }

    @Test
    void decompilerAcceptsAssembledSaltAndSaltuFunction() throws Exception {
        Language language = DefaultLanguageService.getLanguageService().getLanguage(
            new LanguageID("Xtensa:LE:32:esp32s3"));
        Object consumer = new Object();
        ProgramDB program = new ProgramDB("salt-saltu",
            language, language.getCompilerSpecByID(new CompilerSpecID("default")),
            consumer);
        try {
            var start = language.getDefaultSpace().getAddress(0x420bdf4fL);
            byte[] code = fixtureCode();
            int transaction = program.startTransaction("Map oracle function");
            try {
                var block = program.getMemory().createInitializedBlock("text", start,
                    new ByteArrayInputStream(code), code.length, TaskMonitor.DUMMY, false);
                block.setExecute(true);
                Disassembler.getDisassembler(program, TaskMonitor.DUMMY, null)
                    .disassemble(start, new AddressSet(start, start.add(code.length - 1)));
                assertEquals("salt", program.getListing().getInstructionAt(start)
                    .getMnemonicString().toLowerCase());
                var function = program.getFunctionManager().createFunction("oracle", start,
                    new AddressSet(start, start.add(code.length - 1)), SourceType.IMPORTED);
                DecompInterface decompiler = new DecompInterface();
                try {
                    assertTrue(decompiler.openProgram(program));
                    var result = decompiler.decompileFunction(function, 30, TaskMonitor.DUMMY);
                    assertTrue(result.decompileCompleted(), result.getErrorMessage());
                    assertTrue(result.getHighFunction() != null);
                }
                finally {
                    decompiler.dispose();
                }
            }
            finally {
                program.endTransaction(transaction, true);
            }
        }
        finally {
            program.release(consumer);
        }
    }

    private static byte[] fixtureCode() throws Exception {
        try (InputStream source = Esp32S3LanguageTest.class.getResourceAsStream(
                "/fixtures/esp32s3/language/salt-saltu.bin")) {
            if (source == null) {
                throw new IllegalStateException("Missing SALT/SALTU assembler fixture");
            }
            return source.readAllBytes();
        }
    }
}
