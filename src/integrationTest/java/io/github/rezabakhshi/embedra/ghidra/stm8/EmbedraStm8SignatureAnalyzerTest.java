package io.github.rezabakhshi.embedra.ghidra.stm8;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import org.junit.jupiter.api.Test;

class EmbedraStm8SignatureAnalyzerTest {

    @Test
    void metadataAndDefaultsMatchSpecification() {
        EmbedraStm8SignatureAnalyzer analyzer = new EmbedraStm8SignatureAnalyzer();

        assertEquals(EmbedraStm8SignatureAnalyzer.NAME, analyzer.getName());
        assertEquals(EmbedraStm8SignatureAnalyzer.DESCRIPTION, analyzer.getDescription());
        assertEquals(AnalyzerType.FUNCTION_ANALYZER, analyzer.getAnalysisType());
        assertEquals(AnalysisPriority.FUNCTION_ANALYSIS.after().priority(), analyzer.getPriority().priority());
        assertTrue(analyzer.getDefaultEnablement(null));
        assertTrue(analyzer.supportsOneTimeAnalysis());
    }

    @Test
    void canAnalyzeSafelyHandlesNullProgram() {
        EmbedraStm8SignatureAnalyzer analyzer = new EmbedraStm8SignatureAnalyzer();
        assertFalse(analyzer.canAnalyze(null));
    }
}
