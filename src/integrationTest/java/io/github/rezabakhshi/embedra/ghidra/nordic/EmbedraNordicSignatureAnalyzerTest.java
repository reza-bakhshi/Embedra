package io.github.rezabakhshi.embedra.ghidra.nordic;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import org.junit.jupiter.api.Test;

class EmbedraNordicSignatureAnalyzerTest {

    @Test
    void metadataAndDefaultsMatchSpecification() {
        EmbedraNordicSignatureAnalyzer analyzer = new EmbedraNordicSignatureAnalyzer();

        assertEquals(EmbedraNordicSignatureAnalyzer.NAME, analyzer.getName());
        assertEquals(EmbedraNordicSignatureAnalyzer.DESCRIPTION, analyzer.getDescription());
        assertEquals(AnalyzerType.FUNCTION_ANALYZER, analyzer.getAnalysisType());
        assertEquals(AnalysisPriority.FUNCTION_ANALYSIS.after().priority(), analyzer.getPriority().priority());
        assertTrue(analyzer.getDefaultEnablement(null));
        assertTrue(analyzer.supportsOneTimeAnalysis());
    }

    @Test
    void canAnalyzeSafelyHandlesNullProgram() {
        EmbedraNordicSignatureAnalyzer analyzer = new EmbedraNordicSignatureAnalyzer();
        assertFalse(analyzer.canAnalyze(null));
    }
}
