package io.github.rezabakhshi.embedra.analyzers.yara;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Pure Java YARA scanner executing compiled rulesets under ParserLimits and CancellationToken.
 */
public final class YaraScanner {
    private final CompiledYaraRuleset ruleset;

    private final ParserLimits limits;

    public YaraScanner(CompiledYaraRuleset ruleset) {
        this(ruleset, ParserLimits.defaults());
    }

    public YaraScanner(CompiledYaraRuleset ruleset, ParserLimits limits) {
        this.ruleset = Objects.requireNonNull(ruleset, "ruleset");
        this.limits = limits != null ? limits : ParserLimits.defaults();
    }

    public CompiledYaraRuleset ruleset() {
        return ruleset;
    }

    public ParserLimits limits() {
        return limits;
    }

    /**
     * Scans the provided byte array starting at baseAddress 0.
     */
    public List<YaraMatch> scan(byte[] data) throws DiagnosticException {
        return scan(data, 0L, CancellationToken.none());
    }

    /**
     * Scans the provided byte array with explicit base address and cooperative cancellation token.
     */
    public List<YaraMatch> scan(byte[] data, long baseAddress, CancellationToken token)
            throws DiagnosticException {
        Objects.requireNonNull(token, "token");
        token.throwIfCancellationRequested();

        if (data == null || data.length == 0 || ruleset.ruleCount() == 0) {
            return Collections.emptyList();
        }

        if (data.length > limits.maxInputBytes()) {
            throw new DiagnosticException(Diagnostic.error(
                DiagnosticCode.LIMIT_EXCEEDED,
                "Input length (" + data.length + ") exceeds maximum allowed bytes (" + limits.maxInputBytes() + ")",
                null));
        }

        List<YaraMatch> matches = new ArrayList<>();
        int maxMatchesPerPattern = 1_000;

        for (YaraRule rule : ruleset.rules()) {
            token.throwIfCancellationRequested();

            Map<String, List<YaraPattern.MatchRange>> patternMatches = new LinkedHashMap<>();
            for (Map.Entry<String, YaraPattern> entry : rule.patterns().entrySet()) {
                token.throwIfCancellationRequested();
                String pid = entry.getKey();
                YaraPattern pattern = entry.getValue();
                List<YaraPattern.MatchRange> pMatches = pattern.scan(data, maxMatchesPerPattern);
                if (!pMatches.isEmpty()) {
                    patternMatches.put(pid, pMatches);
                }
            }

            YaraCondition.EvaluationContext ctx = new YaraCondition.EvaluationContext(
                baseAddress,
                data.length,
                rule.patterns().keySet(),
                patternMatches
            );

            if (rule.condition().evaluate(ctx)) {
                int firstOffset = Integer.MAX_VALUE;
                int primaryLen = 0;
                for (List<YaraPattern.MatchRange> ranges : patternMatches.values()) {
                    for (YaraPattern.MatchRange mr : ranges) {
                        if (mr.offset() < firstOffset) {
                            firstOffset = mr.offset();
                            primaryLen = mr.length();
                        }
                    }
                }

                if (firstOffset == Integer.MAX_VALUE) {
                    firstOffset = 0;
                    primaryLen = 0;
                }

                matches.add(new YaraMatch(rule, baseAddress, firstOffset, primaryLen, patternMatches));
                if (matches.size() >= limits.maxObjects()) {
                    break;
                }
            }
        }

        return Collections.unmodifiableList(matches);
    }
}
