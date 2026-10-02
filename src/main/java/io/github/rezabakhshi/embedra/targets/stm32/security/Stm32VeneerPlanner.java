package io.github.rezabakhshi.embedra.targets.stm32.security;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Pure, bounded veneer evaluation against one pinned TrustZone record.
 *
 * <p>A candidate is matched only when a pinned non-secure-callable boundary
 * covers its address, a declared transition covers that address, and the
 * candidate carries the transition's evidence id. Every other candidate is
 * rejected with a stable diagnostic. A match is an analysis fact, never a
 * device-support promotion, and it never fabricates a veneer address,
 * instruction semantic, or NSC boundary.</p>
 */
public final class Stm32VeneerPlanner {
    /** Maximum number of non-match details retained before one overflow summary. */
    static final int MAX_DETAILS = 128;

    /** Stable veneer-evaluation diagnostics. */
    public enum Diagnostic {
        NSC_REGION_NOT_PINNED,
        VENEER_OUTSIDE_NSC,
        VENEER_UNEVIDENCED,
        VENEER_EVIDENCE_MISMATCH,
        CANDIDATE_LIMIT_EXCEEDED
    }

    /** Evaluation outcome; a match never establishes device support. */
    public enum Status {
        MATCHED, NO_MATCH, LIMIT_EXCEEDED
    }

    /** One caller-supplied veneer candidate address with its evidence id. */
    public record Candidate(long address, String evidenceId) {
        public Candidate {
            Objects.requireNonNull(evidenceId, "evidenceId");
            if (address < 0 || address > 0xFFFF_FFFFL) {
                throw new IllegalArgumentException("Veneer candidate must fit the 32-bit space");
            }
            if (evidenceId.isBlank()) {
                throw new IllegalArgumentException("Veneer candidate requires an evidence id");
            }
        }
    }

    /** A matched evidence-backed transition. */
    public record Match(long address, String evidenceId, String transitionId,
            String secureTargetRegionId) {
    }

    /** A rejected candidate with a stable diagnostic. */
    public record Rejection(long address, String evidenceId, Diagnostic diagnostic) {
    }

    /** The bounded evaluation result. */
    public record VeneerPlan(String exactPart, Status status, List<Match> matches,
            List<Rejection> rejections, boolean detailsTruncated) {
        public VeneerPlan {
            Objects.requireNonNull(exactPart, "exactPart");
            Objects.requireNonNull(status, "status");
            matches = List.copyOf(matches);
            rejections = List.copyOf(rejections);
        }

        /** Every exact STM32 part remains PLANNED; veneer evaluation never promotes. */
        public String supportState() {
            return "PLANNED";
        }
    }

    private Stm32VeneerPlanner() {
    }

    public static VeneerPlan plan(Stm32SecurityRecord record, List<Candidate> candidates,
            ParserLimits limits, CancellationToken token) throws DiagnosticException {
        Objects.requireNonNull(record, "record");
        Objects.requireNonNull(candidates, "candidates");
        Objects.requireNonNull(limits, "limits");
        Objects.requireNonNull(token, "token");
        List<Candidate> bounded = List.copyOf(candidates);
        if (bounded.size() > limits.maxObjects()) {
            return new VeneerPlan(record.exactPart(), Status.LIMIT_EXCEEDED, List.of(),
                List.of(), true);
        }
        List<Stm32SecurityWindow> boundaries = record.windows().stream()
            .filter(window -> window.attribute() == Stm32SecurityAttribute.NON_SECURE_CALLABLE)
            .toList();
        List<Match> matches = new ArrayList<>();
        List<Rejection> rejections = new ArrayList<>();
        boolean truncated = false;
        for (Candidate candidate : bounded) {
            token.throwIfCancellationRequested();
            if (boundaries.isEmpty()) {
                truncated |= reject(rejections, candidate, Diagnostic.NSC_REGION_NOT_PINNED);
                continue;
            }
            boolean inside = boundaries.stream().anyMatch(window -> window.contains(
                candidate.address()));
            if (!inside) {
                truncated |= reject(rejections, candidate, Diagnostic.VENEER_OUTSIDE_NSC);
                continue;
            }
            List<Stm32VeneerTransition> covering = record.veneerEvidence().transitions().stream()
                .filter(transition -> transition.nscRange().start() <= candidate.address()
                    && candidate.address() < transition.nscRange().endExclusive())
                .toList();
            if (covering.isEmpty()) {
                truncated |= reject(rejections, candidate, Diagnostic.VENEER_UNEVIDENCED);
                continue;
            }
            Stm32VeneerTransition matched = covering.stream()
                .filter(transition -> transition.evidenceId().equals(candidate.evidenceId()))
                .findFirst()
                .orElse(null);
            if (matched == null) {
                truncated |= reject(rejections, candidate, Diagnostic.VENEER_EVIDENCE_MISMATCH);
                continue;
            }
            matches.add(new Match(candidate.address(), candidate.evidenceId(), matched.id(),
                matched.secureTargetRegionId()));
        }
        // Matches are the result; only non-match details are bounded.
        while (rejections.size() > MAX_DETAILS) {
            rejections.remove(rejections.size() - 1);
            truncated = true;
        }
        if (truncated) {
            rejections.add(new Rejection(-1L, "", Diagnostic.CANDIDATE_LIMIT_EXCEEDED));
        }
        return new VeneerPlan(record.exactPart(),
            matches.isEmpty() ? Status.NO_MATCH : Status.MATCHED, matches, rejections,
            truncated);
    }

    private static boolean reject(List<Rejection> rejections, Candidate candidate,
            Diagnostic diagnostic) {
        if (rejections.size() < MAX_DETAILS) {
            rejections.add(new Rejection(candidate.address(), candidate.evidenceId(),
                diagnostic));
            return false;
        }
        return true;
    }
}
