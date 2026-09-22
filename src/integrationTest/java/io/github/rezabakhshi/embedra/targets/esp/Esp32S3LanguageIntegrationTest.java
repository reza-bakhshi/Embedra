package io.github.rezabakhshi.embedra.targets.esp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.util.DefaultLanguageService;
import io.github.rezabakhshi.embedra.targets.LanguageSelection;
import java.io.File;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class Esp32S3LanguageIntegrationTest {
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
    void selectedLanguageAndCompilerResolveInPinnedGhidra() throws Exception {
        Esp32S3TargetProvider provider = new Esp32S3TargetProvider(
            EspressifChipIdRegistry.loadBundled());
        LanguageSelection selection = provider.language();

        Language language = DefaultLanguageService.getLanguageService().getLanguage(
            new LanguageID(selection.languageId()));
        CompilerSpec compiler = language.getCompilerSpecByID(
            new CompilerSpecID(selection.compilerSpecId()));

        assertEquals(selection.languageId(), language.getLanguageID().getIdAsString());
        assertEquals(selection.compilerSpecId(),
            compiler.getCompilerSpecID().getIdAsString());
        assertEquals(selection.instructionAlignmentBytes(), language.getInstructionAlignment());
        assertFalse(language.isBigEndian());
    }
}
