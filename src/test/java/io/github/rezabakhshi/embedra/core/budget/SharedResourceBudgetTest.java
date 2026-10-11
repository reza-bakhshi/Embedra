package io.github.rezabakhshi.embedra.core.budget;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.time.Duration;
import org.junit.jupiter.api.Test;

class SharedResourceBudgetTest {

    @Test
    void defaultsAndBasics() throws Exception {
        SharedResourceBudget nullTokenBudget = new SharedResourceBudget(ParserLimits.defaults(), null);
        assertNotNull(nullTokenBudget.cancellationToken());

        SharedResourceBudget budget = SharedResourceBudget.defaults();
        assertNotNull(budget.limits());
        assertNotNull(budget.cancellationToken());
        assertEquals(0, budget.consumedInputBytes());
        assertEquals(0, budget.consumedExtractedBytes());
        assertEquals(0, budget.consumedAllocationBytes());
        assertEquals(0, budget.createdObjects());
        assertEquals(0, budget.currentNestingDepth());
        assertFalse(budget.elapsed().isNegative());

        budget.trackInputBytes(100);
        assertEquals(100, budget.consumedInputBytes());

        budget.trackExtractedBytes(200);
        assertEquals(200, budget.consumedExtractedBytes());

        budget.trackAllocation(300);
        assertEquals(300, budget.consumedAllocationBytes());

        budget.trackObjects(5);
        assertEquals(5, budget.createdObjects());

        budget.enterNesting();
        assertEquals(1, budget.currentNestingDepth());
        budget.exitNesting();
        assertEquals(0, budget.currentNestingDepth());
        budget.exitNesting(); // check underflow protection
        assertEquals(0, budget.currentNestingDepth());
    }

    @Test
    void rejectsNegativeTrackingInputs() {
        SharedResourceBudget budget = SharedResourceBudget.defaults();
        assertThrows(IllegalArgumentException.class, () -> budget.trackInputBytes(-1));
        assertThrows(IllegalArgumentException.class, () -> budget.trackExtractedBytes(-1));
        assertThrows(IllegalArgumentException.class, () -> budget.trackAllocation(-1));
        assertThrows(IllegalArgumentException.class, () -> budget.trackObjects(-1));
    }

    @Test
    void enforcesInputBytesLimit() {
        ParserLimits limits = new ParserLimits(100, 1000, 1000, 100, 10, Duration.ofSeconds(5));
        SharedResourceBudget budget = SharedResourceBudget.of(limits);

        DiagnosticException ex = assertThrows(DiagnosticException.class, () -> budget.trackInputBytes(101));
        assertEquals(DiagnosticCode.RESOURCE_BUDGET_EXCEEDED, ex.diagnostic().code());
        assertTrue(ex.getMessage().contains("Input bytes budget exceeded"));
    }

    @Test
    void enforcesExtractedBytesLimit() {
        ParserLimits limits = new ParserLimits(1000, 1000, 100, 100, 10, Duration.ofSeconds(5));
        SharedResourceBudget budget = SharedResourceBudget.of(limits);

        DiagnosticException ex = assertThrows(DiagnosticException.class, () -> budget.trackExtractedBytes(101));
        assertEquals(DiagnosticCode.DECOMPRESSION_BOMB_DETECTED, ex.diagnostic().code());
        assertTrue(ex.getMessage().contains("Extracted decompression budget exceeded"));
    }

    @Test
    void enforcesAllocationBytesLimit() {
        ParserLimits limits = new ParserLimits(1000, 100, 1000, 100, 10, Duration.ofSeconds(5));
        SharedResourceBudget budget = SharedResourceBudget.of(limits);

        DiagnosticException ex = assertThrows(DiagnosticException.class, () -> budget.trackAllocation(101));
        assertEquals(DiagnosticCode.RESOURCE_BUDGET_EXCEEDED, ex.diagnostic().code());
        assertTrue(ex.getMessage().contains("Working memory allocation budget exceeded"));
    }

    @Test
    void enforcesObjectCountLimit() {
        ParserLimits limits = new ParserLimits(1000, 1000, 1000, 5, 10, Duration.ofSeconds(5));
        SharedResourceBudget budget = SharedResourceBudget.of(limits);

        DiagnosticException ex = assertThrows(DiagnosticException.class, () -> budget.trackObjects(6));
        assertEquals(DiagnosticCode.RESOURCE_BUDGET_EXCEEDED, ex.diagnostic().code());
        assertTrue(ex.getMessage().contains("Object count budget exceeded"));
    }

    @Test
    void enforcesNestingDepthLimit() throws Exception {
        ParserLimits limits = new ParserLimits(1000, 1000, 1000, 100, 2, Duration.ofSeconds(5));
        SharedResourceBudget budget = SharedResourceBudget.of(limits);

        budget.enterNesting();
        budget.enterNesting();
        DiagnosticException ex = assertThrows(DiagnosticException.class, budget::enterNesting);
        assertEquals(DiagnosticCode.RESOURCE_BUDGET_EXCEEDED, ex.diagnostic().code());
        assertTrue(ex.getMessage().contains("Nesting depth exceeded"));
    }

    @Test
    void enforcesCancellation() {
        CancellationToken token = () -> true;
        SharedResourceBudget budget = new SharedResourceBudget(ParserLimits.defaults(), token);

        DiagnosticException ex = assertThrows(DiagnosticException.class, budget::checkLiveness);
        assertEquals(DiagnosticCode.CANCELLED, ex.diagnostic().code());
    }

    @Test
    void enforcesWallTimeLimit() throws Exception {
        ParserLimits limits = new ParserLimits(1000, 1000, 1000, 100, 10, Duration.ofMillis(10));
        SharedResourceBudget budget = SharedResourceBudget.of(limits);

        Thread.sleep(25);
        DiagnosticException ex = assertThrows(DiagnosticException.class, budget::checkLiveness);
        assertEquals(DiagnosticCode.RESOURCE_BUDGET_EXCEEDED, ex.diagnostic().code());
        assertTrue(ex.getMessage().contains("Wall-time budget exceeded"));
    }
}
