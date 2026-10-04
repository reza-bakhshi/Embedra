package io.github.rezabakhshi.embedra.ghidra.function;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ghidra.GhidraApplicationLayout;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import io.github.rezabakhshi.embedra.ghidra.transaction.GhidraProgramTransaction;
import java.io.File;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class EmbedraFunctionNormalizerIntegrationTest {
    private static final Object CONSUMER = new Object();

    private ProgramDB program;

    @BeforeAll
    static void initializeGhidra() throws Exception {
        if (!Application.isInitialized()) {
            ApplicationConfiguration configuration = new ApplicationConfiguration();
            configuration.setInitializeLogging(false);
            Application.initializeApplication(
                    new GhidraApplicationLayout(new File(System.getenv("GHIDRA_INSTALL_DIR"))),
                    configuration);
        }
    }

    @BeforeEach
    void setUp() throws Exception {
        var language = DefaultLanguageService.getLanguageService().getLanguage(
                new LanguageID("ARM:LE:32:Cortex"));
        program = new ProgramDB("Function Normalizer Test", language,
                language.getCompilerSpecByID(new CompilerSpecID("default")), CONSUMER);

        try (GhidraProgramTransaction tx = GhidraProgramTransaction.start(program, "Create Memory Block")) {
            Address start = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x10000000L);
            MemoryBlock block = program.getMemory().createInitializedBlock(
                    ".text", start, 0x1000L, (byte) 0, TaskMonitor.DUMMY, false);
            block.setRead(true);
            block.setExecute(true);
            tx.commit();
        }
    }

    @AfterEach
    void tearDown() {
        if (program != null) {
            program.release(CONSUMER);
        }
    }

    @Test
    void normalizesUnknownCallingConventionToDefault() throws Exception {
        Address addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x10000100L);
        Function func;
        try (GhidraProgramTransaction tx = GhidraProgramTransaction.start(program, "Create Function")) {
            func = program.getFunctionManager().createFunction(
                    "FUN_10000100", addr, new AddressSet(addr, addr.add(16)), SourceType.USER_DEFINED);
            func.setCallingConvention(Function.UNKNOWN_CALLING_CONVENTION_STRING);
            tx.commit();
        }

        assertTrue(func.hasUnknownCallingConventionName()
                || Function.UNKNOWN_CALLING_CONVENTION_STRING.equals(func.getCallingConventionName()));

        EmbedraFunctionNormalizerReport report = EmbedraFunctionNormalizer.normalize(
                program, null, TaskMonitor.DUMMY);

        assertEquals(1, report.totalExamined());
        assertEquals(1, report.callingConventionsNormalized());
        assertFalse(func.hasUnknownCallingConventionName());
        assertEquals(
                program.getCompilerSpec().getDefaultCallingConvention().getName(),
                func.getCallingConventionName());
    }

    @Test
    void identifiesCommonNonReturningFunctions() throws Exception {
        Address addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x10000200L);
        Function func;
        try (GhidraProgramTransaction tx = GhidraProgramTransaction.start(program, "Create Panic Function")) {
            func = program.getFunctionManager().createFunction(
                    "panic_abort", addr, new AddressSet(addr, addr.add(8)), SourceType.USER_DEFINED);
            tx.commit();
        }

        assertFalse(func.hasNoReturn());

        EmbedraFunctionNormalizerReport report = EmbedraFunctionNormalizer.normalize(
                program, null, TaskMonitor.DUMMY);

        assertEquals(1, report.totalExamined());
        assertEquals(1, report.noReturnMarked());
        assertTrue(func.hasNoReturn());
    }

    @Test
    void analyzerRunsThroughGhidraPipeline() throws Exception {
        Address addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x10000300L);
        try (GhidraProgramTransaction tx = GhidraProgramTransaction.start(program, "Create Func")) {
            Function func = program.getFunctionManager().createFunction(
                    "FUN_10000300", addr, new AddressSet(addr, addr.add(8)), SourceType.USER_DEFINED);
            func.setCallingConvention(Function.UNKNOWN_CALLING_CONVENTION_STRING);
            tx.commit();
        }

        EmbedraFunctionNormalizerAnalyzer analyzer = new EmbedraFunctionNormalizerAnalyzer();
        assertTrue(analyzer.canAnalyze(program));

        MessageLog log = new MessageLog();
        boolean success = analyzer.added(program, program.getMemory(), TaskMonitor.DUMMY, log);
        assertTrue(success);

        Function func = program.getFunctionManager().getFunctionAt(addr);
        assertNotNull(func);
        assertFalse(func.hasUnknownCallingConventionName());
    }
}
