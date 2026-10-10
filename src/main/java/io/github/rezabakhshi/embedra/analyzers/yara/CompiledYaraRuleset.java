package io.github.rezabakhshi.embedra.analyzers.yara;

import io.github.rezabakhshi.embedra.core.ParserLimits;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Immutable compiled collection of YARA rules ready for scanning.
 */
public final class CompiledYaraRuleset {
    private final List<YaraRule> rules;

    private final Map<String, YaraRule> rulesByName;

    public CompiledYaraRuleset(Collection<YaraRule> rules) {
        Objects.requireNonNull(rules, "rules");
        this.rules = Collections.unmodifiableList(new ArrayList<>(rules));
        Map<String, YaraRule> byName = new LinkedHashMap<>();
        for (YaraRule r : rules) {
            byName.put(r.name(), r);
        }
        this.rulesByName = Collections.unmodifiableMap(byName);
    }

    public List<YaraRule> rules() {
        return rules;
    }

    public YaraRule getRule(String name) {
        return rulesByName.get(name);
    }

    public int ruleCount() {
        return rules.size();
    }

    public static CompiledYaraRuleset loadBuiltinRules(boolean crypto, boolean formats) {
        return loadBuiltinRules(crypto, formats, false);
    }

    public static CompiledYaraRuleset loadBuiltinRules(boolean crypto, boolean formats, boolean threats) {
        Builder builder = builder();
        try {
            if (crypto) {
                builder.addResource("/rules/crypto/ciphers.yar");
                builder.addResource("/rules/crypto/hashes.yar");
            }
            if (formats) {
                builder.addResource("/rules/formats/containers.yar");
                builder.addResource("/rules/formats/encodings.yar");
            }
            if (threats) {
                builder.addResource("/rules/threats/malware.yar");
                builder.addResource("/rules/threats/backdoors.yar");
            }
        } catch (Exception e) {
            throw new IllegalStateException("Failed to load built-in YARA rules", e);
        }
        return builder.build();
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private final List<YaraRule> rules = new ArrayList<>();

        private ParserLimits limits = ParserLimits.defaults();

        public Builder withLimits(ParserLimits limits) {
            this.limits = Objects.requireNonNull(limits, "limits");
            return this;
        }

        public Builder addRule(YaraRule rule) {
            this.rules.add(Objects.requireNonNull(rule, "rule"));
            return this;
        }

        public Builder addRules(Collection<YaraRule> rules) {
            this.rules.addAll(Objects.requireNonNull(rules, "rules"));
            return this;
        }

        public Builder addSource(String source) throws YaraParseException {
            YaraRuleParser parser = new YaraRuleParser(source, limits);
            this.rules.addAll(parser.parseRules());
            return this;
        }

        public Builder addResource(String resourcePath) throws IOException, YaraParseException {
            InputStream in = getClass().getResourceAsStream(resourcePath);
            if (in == null) {
                // Try with leading slash if not present
                if (!resourcePath.startsWith("/")) {
                    in = getClass().getResourceAsStream("/" + resourcePath);
                }
            }
            if (in == null) {
                throw new IOException("YARA resource not found: " + resourcePath);
            }
            try (InputStream stream = in) {
                this.rules.addAll(YaraRuleParser.parse(stream));
            }
            return this;
        }

        public Builder addFile(Path path) throws IOException, YaraParseException {
            try (InputStream in = Files.newInputStream(path)) {
                this.rules.addAll(YaraRuleParser.parse(in));
            }
            return this;
        }

        public Builder addDirectory(Path dir) throws IOException, YaraParseException {
            if (!Files.isDirectory(dir)) {
                return this;
            }
            try (DirectoryStream<Path> stream = Files.newDirectoryStream(dir, "*.{yar,yara}")) {
                for (Path entry : stream) {
                    if (Files.isRegularFile(entry)) {
                        addFile(entry);
                    }
                }
            }
            return this;
        }

        public CompiledYaraRuleset build() {
            return new CompiledYaraRuleset(rules);
        }
    }
}
