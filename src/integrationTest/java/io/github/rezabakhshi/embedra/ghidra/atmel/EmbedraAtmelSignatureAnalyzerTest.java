package io.github.rezabakhshi.embedra.ghidra.atmel;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import org.junit.jupiter.api.Test;

class EmbedraAtmelSignatureAnalyzerTest {

    @Test
    void metadataAndDefaultsMatchSpecification() {
        EmbedraAtmelSignatureAnalyzer analyzer = new EmbedraAtmelSignatureAnalyzer();

        assertEquals(EmbedraAtmelSignatureAnalyzer.NAME, analyzer.getName());
        assertEquals(EmbedraAtmelSignatureAnalyzer.DESCRIPTION, analyzer.getDescription());
        assertEquals(AnalyzerType.FUNCTION_ANALYZER, analyzer.getAnalysisType());
        assertEquals(AnalysisPriority.FUNCTION_ANALYSIS.after().priority(), analyzer.getPriority().priority());
        assertTrue(analyzer.getDefaultEnablement(null));
        assertTrue(analyzer.supportsOneTimeAnalysis());
    }

    @Test
    void canAnalyzeSafelyHandlesNullProgram() {
        EmbedraAtmelSignatureAnalyzer analyzer = new EmbedraAtmelSignatureAnalyzer();
        assertFalse(analyzer.canAnalyze(null));
    }
}
