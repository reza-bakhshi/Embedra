package io.github.rezabakhshi.embedra.analyzers.yara;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * AST and evaluation logic for YARA rule conditions.
 */
@FunctionalInterface
public interface YaraCondition {

    boolean evaluate(EvaluationContext context);

    record EvaluationContext(
            long baseAddress,
            int bufferLength,
            Set<String> allRulePatterns,
            Map<String, List<YaraPattern.MatchRange>> matchesByPattern) {

        public List<YaraPattern.MatchRange> matches(String patternId) {
            return matchesByPattern.getOrDefault(patternId, Collections.emptyList());
        }

        public int matchCount(String patternId) {
            return matches(patternId).size();
        }
    }

    record TrueCondition() implements YaraCondition {
        @Override
        public boolean evaluate(EvaluationContext context) {
            return true;
        }
    }

    record FalseCondition() implements YaraCondition {
        @Override
        public boolean evaluate(EvaluationContext context) {
            return false;
        }
    }

    record PatternMatchCondition(String patternId) implements YaraCondition {
        public PatternMatchCondition {
            Objects.requireNonNull(patternId, "patternId");
        }

        @Override
        public boolean evaluate(EvaluationContext context) {
            return !context.matches(patternId).isEmpty();
        }
    }

    record PatternCountCondition(String patternId, ComparisonOp op, int expected) implements YaraCondition {
        public PatternCountCondition {
            Objects.requireNonNull(patternId, "patternId");
            Objects.requireNonNull(op, "op");
        }

        @Override
        public boolean evaluate(EvaluationContext context) {
            int count = context.matchCount(patternId);
            return switch (op) {
                case EQ -> count == expected;
                case NE -> count != expected;
                case GT -> count > expected;
                case GTE -> count >= expected;
                case LT -> count < expected;
                case LTE -> count <= expected;
            };
        }
    }

    enum ComparisonOp {
        EQ, NE, GT, GTE, LT, LTE
    }

    record PatternAtCondition(String patternId, long offset) implements YaraCondition {
        public PatternAtCondition {
            Objects.requireNonNull(patternId, "patternId");
        }

        @Override
        public boolean evaluate(EvaluationContext context) {
            for (YaraPattern.MatchRange mr : context.matches(patternId)) {
                if (mr.offset() == offset) {
                    return true;
                }
            }
            return false;
        }
    }

    record PatternInCondition(String patternId, long start, long end) implements YaraCondition {
        public PatternInCondition {
            Objects.requireNonNull(patternId, "patternId");
        }

        @Override
        public boolean evaluate(EvaluationContext context) {
            for (YaraPattern.MatchRange mr : context.matches(patternId)) {
                if (mr.offset() >= start && mr.offset() <= end) {
                    return true;
                }
            }
            return false;
        }
    }

    record NotCondition(YaraCondition inner) implements YaraCondition {
        public NotCondition {
            Objects.requireNonNull(inner, "inner");
        }

        @Override
        public boolean evaluate(EvaluationContext context) {
            return !inner.evaluate(context);
        }
    }

    record AndCondition(YaraCondition left, YaraCondition right) implements YaraCondition {
        public AndCondition {
            Objects.requireNonNull(left, "left");
            Objects.requireNonNull(right, "right");
        }

        @Override
        public boolean evaluate(EvaluationContext context) {
            return left.evaluate(context) && right.evaluate(context);
        }
    }

    record OrCondition(YaraCondition left, YaraCondition right) implements YaraCondition {
        public OrCondition {
            Objects.requireNonNull(left, "left");
            Objects.requireNonNull(right, "right");
        }

        @Override
        public boolean evaluate(EvaluationContext context) {
            return left.evaluate(context) || right.evaluate(context);
        }
    }

    record SetCondition(int requiredCount, boolean all, Set<String> targetPatterns) implements YaraCondition {
        public SetCondition {
            Objects.requireNonNull(targetPatterns, "targetPatterns");
        }

        public static SetCondition anyThem() {
            return new SetCondition(1, false, Collections.emptySet());
        }

        public static SetCondition allThem() {
            return new SetCondition(0, true, Collections.emptySet());
        }

        public static SetCondition countThem(int count) {
            return new SetCondition(count, false, Collections.emptySet());
        }

        public static SetCondition anyOf(Collection<String> patterns) {
            return new SetCondition(1, false, Set.copyOf(patterns));
        }

        public static SetCondition allOf(Collection<String> patterns) {
            return new SetCondition(patterns.size(), true, Set.copyOf(patterns));
        }

        public static SetCondition countOf(int count, Collection<String> patterns) {
            return new SetCondition(count, false, Set.copyOf(patterns));
        }

        @Override
        public boolean evaluate(EvaluationContext context) {
            Set<String> pool = targetPatterns.isEmpty() ? context.allRulePatterns() : targetPatterns;
            if (pool.isEmpty()) {
                return false;
            }

            int matched = 0;
            for (String pid : pool) {
                if (!context.matches(pid).isEmpty()) {
                    matched++;
                }
            }

            if (all) {
                return matched == pool.size();
            }
            return matched >= requiredCount;
        }
    }
}
