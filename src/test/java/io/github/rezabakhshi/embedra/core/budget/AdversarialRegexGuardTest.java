package io.github.rezabakhshi.embedra.core.budget;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.lang.reflect.Constructor;
import java.time.Duration;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

class AdversarialRegexGuardTest {

    @Test
    void rejectsNullInputs() {
        SharedResourceBudget budget = SharedResourceBudget.defaults();
        Pattern pattern = Pattern.compile("test");

        assertThrows(NullPointerException.class, () -> AdversarialRegexGuard.findSafely(null, "abc", budget));
        assertThrows(NullPointerException.class, () -> AdversarialRegexGuard.findSafely(pattern, null, budget));
        assertThrows(NullPointerException.class, () -> AdversarialRegexGuard.findSafely(pattern, "abc", null));

        assertThrows(NullPointerException.class, () -> AdversarialRegexGuard.matchesSafely(null, "abc", budget));
        assertThrows(NullPointerException.class, () -> AdversarialRegexGuard.matchesSafely(pattern, null, budget));
        assertThrows(NullPointerException.class, () -> AdversarialRegexGuard.matchesSafely(pattern, "abc", null));
    }

    @Test
    void matchesAndFindsSafelyOnBenignInput() throws Exception {
        SharedResourceBudget budget = SharedResourceBudget.defaults();
        Pattern numPattern = Pattern.compile("\\d+");

        assertTrue(AdversarialRegexGuard.findSafely(numPattern, "abc123def", budget));
        assertFalse(AdversarialRegexGuard.findSafely(numPattern, "abcdef", budget));

        Pattern fullNumPattern = Pattern.compile("\\d{5}");
        assertTrue(AdversarialRegexGuard.matchesSafely(fullNumPattern, "12345", budget));
        assertFalse(AdversarialRegexGuard.matchesSafely(fullNumPattern, "1234a", budget));

        assertTrue(budget.consumedInputBytes() > 0);
    }

    @Test
    @Timeout(5)
    void rejectsCatastrophicBacktrackingInFindSafely() {
        Pattern evilPattern = Pattern.compile("^((a+)+)+$");
        String evilInput = "a".repeat(22) + "!";

        ParserLimits limits = new ParserLimits(10_000, 10_000, 10_000, 100, 10, Duration.ofMillis(20));
        SharedResourceBudget budget = SharedResourceBudget.of(limits);

        DiagnosticException ex = assertThrows(DiagnosticException.class, () ->
                AdversarialRegexGuard.findSafely(evilPattern, evilInput, budget));

        assertEquals(DiagnosticCode.REGEX_TIMEOUT_EXCEEDED, ex.diagnostic().code());
        assertTrue(ex.getMessage().contains("ReDoS protection"));
    }

    @Test
    @Timeout(5)
    void rejectsCatastrophicBacktrackingInMatchesSafely() {
        Pattern evilPattern = Pattern.compile("^((a+)+)+$");
        String evilInput = "a".repeat(22) + "!";

        ParserLimits limits = new ParserLimits(10_000, 10_000, 10_000, 100, 10, Duration.ofMillis(20));
        SharedResourceBudget budget = SharedResourceBudget.of(limits);

        DiagnosticException ex = assertThrows(DiagnosticException.class, () ->
                AdversarialRegexGuard.matchesSafely(evilPattern, evilInput, budget));

        assertEquals(DiagnosticCode.REGEX_TIMEOUT_EXCEEDED, ex.diagnostic().code());
        assertTrue(ex.getMessage().contains("ReDoS protection"));
    }

    @Test
    void testSubSequenceAndToStringCoverage() throws Exception {
        SharedResourceBudget budget = SharedResourceBudget.defaults();
        Pattern pattern = Pattern.compile("^hello$");
        assertTrue(AdversarialRegexGuard.matchesSafely(pattern, "hello", budget));
    }

    @Test
    void testPrivateConstructor() throws Exception {
        Constructor<AdversarialRegexGuard> constructor = AdversarialRegexGuard.class.getDeclaredConstructor();
        constructor.setAccessible(true);
        assertNotNull(constructor.newInstance());
    }
}
