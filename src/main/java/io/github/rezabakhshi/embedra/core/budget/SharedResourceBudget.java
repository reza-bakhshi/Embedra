package io.github.rezabakhshi.embedra.core.budget;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Thread-safe shared resource budget tracker enforcing ParserLimits, wall-time timeouts,
 * and cooperative cancellation across parsers, analyzers, and enrichments (AN-009, Section 5.3).
 */
public final class SharedResourceBudget {

    private final ParserLimits limits;

    private final CancellationToken token;

    private final long startNanos;

    private final AtomicLong consumedInputBytes = new AtomicLong(0);

    private final AtomicLong consumedExtractedBytes = new AtomicLong(0);

    private final AtomicLong consumedAllocationBytes = new AtomicLong(0);

    private final AtomicLong createdObjects = new AtomicLong(0);

    private final AtomicInteger currentNestingDepth = new AtomicInteger(0);

    public SharedResourceBudget(ParserLimits limits, CancellationToken token) {
        this.limits = Objects.requireNonNull(limits, "limits must not be null");
        this.token = token == null ? CancellationToken.none() : token;
        this.startNanos = System.nanoTime();
    }

    public static SharedResourceBudget defaults() {
        return new SharedResourceBudget(ParserLimits.defaults(), CancellationToken.none());
    }

    public static SharedResourceBudget of(ParserLimits limits) {
        return new SharedResourceBudget(limits, CancellationToken.none());
    }

    public ParserLimits limits() {
        return limits;
    }

    public CancellationToken cancellationToken() {
        return token;
    }

    public long consumedInputBytes() {
        return consumedInputBytes.get();
    }

    public long consumedExtractedBytes() {
        return consumedExtractedBytes.get();
    }

    public long consumedAllocationBytes() {
        return consumedAllocationBytes.get();
    }

    public long createdObjects() {
        return createdObjects.get();
    }

    public int currentNestingDepth() {
        return currentNestingDepth.get();
    }

    public Duration elapsed() {
        long elapsedNanos = System.nanoTime() - startNanos;
        return Duration.ofNanos(Math.max(0, elapsedNanos));
    }

    /**
     * Checks cooperative cancellation and elapsed wall-time.
     */
    public void checkLiveness() throws DiagnosticException {
        if (token.isCancellationRequested()) {
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.CANCELLED,
                    "Operation cancelled by cooperative cancellation token"));
        }
        long elapsedNanos = System.nanoTime() - startNanos;
        if (elapsedNanos > limits.maxWallTime().toNanos()) {
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.RESOURCE_BUDGET_EXCEEDED,
                    String.format("Wall-time budget exceeded: elapsed %d ms, max %d ms",
                            elapsedNanos / 1_000_000, limits.maxWallTime().toMillis())));
        }
    }

    /**
     * Tracks ingested raw input bytes against limits.maxInputBytes.
     */
    public void trackInputBytes(long bytes) throws DiagnosticException {
        if (bytes < 0) {
            throw new IllegalArgumentException("Bytes must not be negative: " + bytes);
        }
        checkLiveness();
        long total = consumedInputBytes.addAndGet(bytes);
        if (total > limits.maxInputBytes()) {
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.RESOURCE_BUDGET_EXCEEDED,
                    String.format("Input bytes budget exceeded: %d bytes (limit: %d)",
                            total, limits.maxInputBytes())));
        }
    }

    /**
     * Tracks extracted decompressed bytes against limits.maxExtractedBytes.
     */
    public void trackExtractedBytes(long bytes) throws DiagnosticException {
        if (bytes < 0) {
            throw new IllegalArgumentException("Bytes must not be negative: " + bytes);
        }
        checkLiveness();
        long total = consumedExtractedBytes.addAndGet(bytes);
        if (total > limits.maxExtractedBytes()) {
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.DECOMPRESSION_BOMB_DETECTED,
                    String.format("Extracted decompression budget exceeded: %d bytes (limit: %d)",
                            total, limits.maxExtractedBytes())));
        }
    }

    /**
     * Tracks working memory allocation against limits.maxAllocationBytes.
     */
    public void trackAllocation(long bytes) throws DiagnosticException {
        if (bytes < 0) {
            throw new IllegalArgumentException("Bytes must not be negative: " + bytes);
        }
        checkLiveness();
        long total = consumedAllocationBytes.addAndGet(bytes);
        if (total > limits.maxAllocationBytes()) {
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.RESOURCE_BUDGET_EXCEEDED,
                    String.format("Working memory allocation budget exceeded: %d bytes (limit: %d)",
                            total, limits.maxAllocationBytes())));
        }
    }

    /**
     * Tracks parsed or created objects against limits.maxObjects.
     */
    public void trackObjects(long count) throws DiagnosticException {
        if (count < 0) {
            throw new IllegalArgumentException("Count must not be negative: " + count);
        }
        checkLiveness();
        long total = createdObjects.addAndGet(count);
        if (total > limits.maxObjects()) {
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.RESOURCE_BUDGET_EXCEEDED,
                    String.format("Object count budget exceeded: %d objects (limit: %d)",
                            total, limits.maxObjects())));
        }
    }

    /**
     * Increments nesting depth and checks against limits.maxNestingDepth.
     */
    public void enterNesting() throws DiagnosticException {
        checkLiveness();
        int depth = currentNestingDepth.incrementAndGet();
        if (depth > limits.maxNestingDepth()) {
            throw new DiagnosticException(Diagnostic.error(
                    DiagnosticCode.RESOURCE_BUDGET_EXCEEDED,
                    String.format("Nesting depth exceeded: depth %d (limit: %d)",
                            depth, limits.maxNestingDepth())));
        }
    }

    /**
     * Decrements nesting depth safely.
     */
    public void exitNesting() {
        currentNestingDepth.updateAndGet(d -> Math.max(0, d - 1));
    }
}
