package io.github.rezabakhshi.embedra.analyzers.plugins;

import io.github.rezabakhshi.embedra.analyzers.strings.ExtractedString;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Built-in bounded scanner executing declarative pattern rules (AN-009).
 */
public final class DeclarativeScannerPlugin implements ScannerPlugin {

    private final ScannerPluginManifest manifest;

    private final Map<String, Pattern> compiledPatterns = new ConcurrentHashMap<>();

    private final Map<String, byte[]> parsedHexBytes = new ConcurrentHashMap<>();

    public DeclarativeScannerPlugin(ScannerPluginManifest manifest) {
        this.manifest = Objects.requireNonNull(manifest, "manifest must not be null");
        if (manifest.pluginType() != PluginType.DECLARATIVE_RULE) {
            throw new IllegalArgumentException("Manifest pluginType must be DECLARATIVE_RULE");
        }
        for (DeclarativeRuleDefinition rule : manifest.declarativeRules()) {
            if (rule.matcherType() == DeclarativeMatcherType.REGEX && !rule.pattern().isBlank()) {
                compiledPatterns.put(rule.ruleId(), Pattern.compile(rule.pattern()));
            } else if (rule.matcherType() == DeclarativeMatcherType.HEX_BYTES && !rule.pattern().isBlank()) {
                parsedHexBytes.put(rule.ruleId(), parseHex(rule.pattern()));
            }
        }
    }

    @Override
    public ScannerPluginManifest manifest() {
        return manifest;
    }

    @Override
    public List<ScannerPluginFinding> scan(PluginScanContext context) throws DiagnosticException {
        Objects.requireNonNull(context, "context must not be null");
        context.cancellationToken().throwIfCancellationRequested();

        List<ScannerPluginFinding> findings = new ArrayList<>();
        int maxFindings = context.budget().maxFindings();

        for (DeclarativeRuleDefinition rule : manifest.declarativeRules()) {
            context.cancellationToken().throwIfCancellationRequested();
            if (findings.size() >= maxFindings) {
                break;
            }

            switch (rule.matcherType()) {
                case REGEX -> scanRegex(rule, context, findings, maxFindings);
                case HEX_BYTES -> scanHexBytes(rule, context, findings, maxFindings);
                case EXACT_STRING -> scanExactString(rule, context, findings, maxFindings);
                case ENTROPY -> scanEntropy(rule, context, findings, maxFindings);
                default -> { /* ignore */ }
            }
        }

        return Collections.unmodifiableList(findings);
    }

    private void scanRegex(
            DeclarativeRuleDefinition rule,
            PluginScanContext context,
            List<ScannerPluginFinding> findings,
            int maxFindings) throws DiagnosticException {
        Pattern pattern = compiledPatterns.computeIfAbsent(rule.ruleId(), k -> Pattern.compile(rule.pattern()));

        if (!context.strings().isEmpty()) {
            for (ExtractedString es : context.strings()) {
                context.cancellationToken().throwIfCancellationRequested();
                if (findings.size() >= maxFindings) {
                    return;
                }
                String text = es.content();
                // Bound checked string length for ReDoS defense
                if (text.length() > 4096) {
                    text = text.substring(0, 4096);
                }
                Matcher matcher = pattern.matcher(text);
                if (matcher.find()) {
                    String matchedText = matcher.group();
                    findings.add(new ScannerPluginFinding(
                            manifest.pluginId() + ":" + rule.ruleId() + ":" + Long.toHexString(es.offset()),
                            manifest.pluginId(),
                            rule.category(),
                            rule.subcategory(),
                            rule.severity(),
                            rule.confidence(),
                            rule.confidenceScore(),
                            context.platform(),
                            es.offset() + matcher.start(),
                            matchedText.length(),
                            matchedText,
                            rule.description(),
                            rule.secret(),
                            Map.of("ruleId", rule.ruleId(), "matchKind", "REGEX")
                    ));
                }
            }
        } else if (context.data().length > 0) {
            String text = new String(context.data(), 0, Math.min(context.data().length, 65536),
                    StandardCharsets.ISO_8859_1);
            Matcher matcher = pattern.matcher(text);
            while (matcher.find()) {
                context.cancellationToken().throwIfCancellationRequested();
                if (findings.size() >= maxFindings) {
                    return;
                }
                String matched = matcher.group();
                findings.add(new ScannerPluginFinding(
                        manifest.pluginId() + ":" + rule.ruleId() + ":" + Long.toHexString(context.baseAddress()
                                + matcher.start()),
                        manifest.pluginId(),
                        rule.category(),
                        rule.subcategory(),
                        rule.severity(),
                        rule.confidence(),
                        rule.confidenceScore(),
                        context.platform(),
                        context.baseAddress() + matcher.start(),
                        matched.length(),
                        matched,
                        rule.description(),
                        rule.secret(),
                        Map.of("ruleId", rule.ruleId(), "matchKind", "REGEX")
                ));
            }
        }
    }

    private void scanHexBytes(
            DeclarativeRuleDefinition rule,
            PluginScanContext context,
            List<ScannerPluginFinding> findings,
            int maxFindings) throws DiagnosticException {
        byte[] needle = parsedHexBytes.computeIfAbsent(rule.ruleId(), k -> parseHex(rule.pattern()));
        if (needle.length == 0 || context.data().length < needle.length) {
            return;
        }

        byte[] hay = context.data();
        int maxIndex = hay.length - needle.length;

        for (int i = 0; i <= maxIndex; i++) {
            if ((i & 0x3FF) == 0) {
                context.cancellationToken().throwIfCancellationRequested();
            }
            if (findings.size() >= maxFindings) {
                return;
            }

            boolean match = true;
            for (int j = 0; j < needle.length; j++) {
                if (hay[i + j] != needle[j]) {
                    match = false;
                    break;
                }
            }

            if (match) {
                long addr = context.baseAddress() + i;
                findings.add(new ScannerPluginFinding(
                        manifest.pluginId() + ":" + rule.ruleId() + ":" + Long.toHexString(addr),
                        manifest.pluginId(),
                        rule.category(),
                        rule.subcategory(),
                        rule.severity(),
                        rule.confidence(),
                        rule.confidenceScore(),
                        context.platform(),
                        addr,
                        needle.length,
                        rule.pattern(),
                        rule.description(),
                        rule.secret(),
                        Map.of("ruleId", rule.ruleId(), "matchKind", "HEX_BYTES")
                ));
            }
        }
    }

    private void scanExactString(
            DeclarativeRuleDefinition rule,
            PluginScanContext context,
            List<ScannerPluginFinding> findings,
            int maxFindings) throws DiagnosticException {
        String target = rule.pattern();
        if (target.isBlank()) {
            return;
        }

        if (!context.strings().isEmpty()) {
            for (ExtractedString es : context.strings()) {
                context.cancellationToken().throwIfCancellationRequested();
                if (findings.size() >= maxFindings) {
                    return;
                }
                int idx = es.content().indexOf(target);
                if (idx >= 0) {
                    long addr = es.offset() + idx;
                    findings.add(new ScannerPluginFinding(
                            manifest.pluginId() + ":" + rule.ruleId() + ":" + Long.toHexString(addr),
                            manifest.pluginId(),
                            rule.category(),
                            rule.subcategory(),
                            rule.severity(),
                            rule.confidence(),
                            rule.confidenceScore(),
                            context.platform(),
                            addr,
                            target.length(),
                            target,
                            rule.description(),
                            rule.secret(),
                            Map.of("ruleId", rule.ruleId(), "matchKind", "EXACT_STRING")
                    ));
                }
            }
        }
    }

    private void scanEntropy(
            DeclarativeRuleDefinition rule,
            PluginScanContext context,
            List<ScannerPluginFinding> findings,
            int maxFindings) throws DiagnosticException {
        byte[] data = context.data();
        int windowSize = 256;
        int step = 128;
        if (data.length < windowSize) {
            return;
        }

        double min = rule.minEntropy() != null ? rule.minEntropy() : 0.0;
        double max = rule.maxEntropy() != null ? rule.maxEntropy() : 8.0;

        for (int i = 0; i <= data.length - windowSize; i += step) {
            context.cancellationToken().throwIfCancellationRequested();
            if (findings.size() >= maxFindings) {
                return;
            }

            double entropy = calculateShannonEntropy(data, i, windowSize);
            if (entropy >= min && entropy <= max) {
                long addr = context.baseAddress() + i;
                findings.add(new ScannerPluginFinding(
                        manifest.pluginId() + ":" + rule.ruleId() + ":" + Long.toHexString(addr),
                        manifest.pluginId(),
                        rule.category(),
                        rule.subcategory(),
                        rule.severity(),
                        rule.confidence(),
                        rule.confidenceScore(),
                        context.platform(),
                        addr,
                        windowSize,
                        String.format(java.util.Locale.ROOT, "Entropy: %.3f", entropy),
                        rule.description(),
                        rule.secret(),
                        Map.of("ruleId", rule.ruleId(), "matchKind", "ENTROPY",
                                "entropy", String.format(java.util.Locale.ROOT, "%.4f", entropy))
                ));
            }
        }
    }

    private static double calculateShannonEntropy(byte[] data, int offset, int length) {
        int[] freq = new int[256];
        for (int i = 0; i < length; i++) {
            freq[data[offset + i] & 0xFF]++;
        }
        double entropy = 0.0;
        double log2 = Math.log(2);
        for (int count : freq) {
            if (count > 0) {
                double p = (double) count / length;
                entropy -= p * (Math.log(p) / log2);
            }
        }
        return entropy;
    }

    private static byte[] parseHex(String hex) {
        String clean = hex.replaceAll("\\s+", "");
        if (clean.length() % 2 != 0) {
            throw new IllegalArgumentException("Hex string must have an even number of characters: " + hex);
        }
        byte[] bytes = new byte[clean.length() / 2];
        for (int i = 0; i < clean.length(); i += 2) {
            bytes[i / 2] = (byte) Integer.parseInt(clean.substring(i, i + 2), 16);
        }
        return bytes;
    }
}
