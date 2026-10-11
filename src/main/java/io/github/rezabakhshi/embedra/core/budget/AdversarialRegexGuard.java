package io.github.rezabakhshi.embedra.core.budget;

import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Executes regular expressions safely against untrusted input, protecting against
 * Catastrophic Backtracking (ReDoS) and unbounded CPU consumption (Section 5.3).
 */
public final class AdversarialRegexGuard {

    private AdversarialRegexGuard() {
    }

    /**
     * Executes regex find() over input with time and input length bounding under the budget.
     */
    public static boolean findSafely(
            Pattern pattern,
            CharSequence input,
            SharedResourceBudget budget) throws DiagnosticException {
        Objects.requireNonNull(pattern, "pattern must not be null");
        Objects.requireNonNull(input, "input must not be null");
        Objects.requireNonNull(budget, "budget must not be null");

        budget.checkLiveness();
        budget.trackInputBytes(input.length());

        TimeoutCharSequence boundedInput = new TimeoutCharSequence(input, budget);
        Matcher matcher = pattern.matcher(boundedInput);

        try {
            return matcher.find();
        } catch (TimeoutRegexException e) {
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.REGEX_TIMEOUT_EXCEEDED,
                    "Regular expression evaluation exceeded wall-time budget (ReDoS protection): "
                            + pattern.pattern()));
        }
    }

    /**
     * Executes regex matches() over input with time bounding.
     */
    public static boolean matchesSafely(
            Pattern pattern,
            CharSequence input,
            SharedResourceBudget budget) throws DiagnosticException {
        Objects.requireNonNull(pattern, "pattern must not be null");
        Objects.requireNonNull(input, "input must not be null");
        Objects.requireNonNull(budget, "budget must not be null");

        budget.checkLiveness();
        budget.trackInputBytes(input.length());

        TimeoutCharSequence boundedInput = new TimeoutCharSequence(input, budget);
        Matcher matcher = pattern.matcher(boundedInput);

        try {
            return matcher.matches();
        } catch (TimeoutRegexException e) {
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.REGEX_TIMEOUT_EXCEEDED,
                    "Regular expression evaluation exceeded wall-time budget (ReDoS protection): "
                            + pattern.pattern()));
        }
    }

    private static final class TimeoutCharSequence implements CharSequence {
        private final CharSequence delegate;

        private final SharedResourceBudget budget;

        private int count = 0;

        TimeoutCharSequence(CharSequence delegate, SharedResourceBudget budget) {
            this.delegate = delegate;
            this.budget = budget;
        }

        @Override
        public int length() {
            return delegate.length();
        }

        @Override
        public char charAt(int index) {
            // Check budget liveness every 64 iterations to avoid timer call overhead
            if ((count++ & 0x3F) == 0) {
                try {
                    budget.checkLiveness();
                } catch (DiagnosticException e) {
                    throw new TimeoutRegexException(e.getMessage());
                }
            }
            return delegate.charAt(index);
        }

        @Override
        public CharSequence subSequence(int start, int end) {
            return new TimeoutCharSequence(delegate.subSequence(start, end), budget);
        }

        @Override
        public String toString() {
            return delegate.toString();
        }
    }

    private static final class TimeoutRegexException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        TimeoutRegexException(String message) {
            super(message);
        }
    }
}
