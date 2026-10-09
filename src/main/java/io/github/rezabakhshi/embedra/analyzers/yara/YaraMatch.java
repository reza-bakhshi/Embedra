package io.github.rezabakhshi.embedra.analyzers.yara;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Result of a successful YARA rule match on a memory buffer.
 */
public record YaraMatch(
        YaraRule rule,
        long baseAddress,
        int offset,
        int length,
        Map<String, List<YaraPattern.MatchRange>> patternMatches) {

    public YaraMatch {
        Objects.requireNonNull(rule, "rule");
        Objects.requireNonNull(patternMatches, "patternMatches");
        if (offset < 0 || length < 0) {
            throw new IllegalArgumentException("Invalid match bounds: offset=" + offset + ", length=" + length);
        }
    }

    public long address() {
        return baseAddress + offset;
    }

    public String ruleName() {
        return rule.name();
    }

    public String description() {
        return rule.description();
    }

    public String category() {
        return rule.category();
    }

    public String algorithm() {
        return rule.algorithm();
    }

    public String confidence() {
        return rule.confidence();
    }

    public List<YaraPattern.MatchRange> matchesFor(String patternId) {
        return patternMatches.getOrDefault(patternId, Collections.emptyList());
    }
}
