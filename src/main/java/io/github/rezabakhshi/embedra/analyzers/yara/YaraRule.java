package io.github.rezabakhshi.embedra.analyzers.yara;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Immutable representation of a parsed YARA rule.
 */
public record YaraRule(
        String name,
        Set<String> tags,
        Map<String, Object> meta,
        Map<String, YaraPattern> patterns,
        YaraCondition condition) {

    public YaraRule {
        Objects.requireNonNull(name, "name");
        tags = Collections.unmodifiableSet(new LinkedHashSet<>(Objects.requireNonNull(tags, "tags")));
        meta = Collections.unmodifiableMap(new LinkedHashMap<>(Objects.requireNonNull(meta, "meta")));
        patterns = Collections.unmodifiableMap(new LinkedHashMap<>(Objects.requireNonNull(patterns, "patterns")));
        Objects.requireNonNull(condition, "condition");
    }

    public String metaString(String key) {
        Object val = meta.get(key);
        return val != null ? val.toString() : null;
    }

    public String description() {
        String desc = metaString("description");
        return desc != null ? desc : name;
    }

    public String category() {
        return metaString("category");
    }

    public String algorithm() {
        return metaString("algorithm");
    }

    public String confidence() {
        return metaString("confidence");
    }
}
