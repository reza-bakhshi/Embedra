package io.github.rezabakhshi.embedra.core.report;

import io.github.rezabakhshi.embedra.core.diagnostic.Diagnostic;
import io.github.rezabakhshi.embedra.core.io.AddressRange;
import io.github.rezabakhshi.embedra.core.io.SourceRange;
import io.github.rezabakhshi.embedra.core.model.Confidence;
import io.github.rezabakhshi.embedra.core.model.Evidence;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.TreeMap;

/** Versioned canonical analysis report with deterministic section ordering. */
public record CanonicalReport(
        String schemaId,
        String toolBuild,
        List<Input> inputs,
        List<Component> providers,
        List<Component> packs,
        List<Validation> validations,
        List<Mapping> mappings,
        List<AppliedSymbol> appliedSymbols,
        List<AppliedType> appliedTypes,
        Map<String, String> metadata,
        Optional<ExecutionTopologyReport> executionTopology,
        List<Finding> findings,
        List<Diagnostic> diagnostics,
        Reproducibility reproducibility) {
    public static final String SCHEMA_ID = "urn:embedra:schema:canonical-report:1";

    public CanonicalReport {
        Objects.requireNonNull(schemaId, "schemaId");
        requireText(toolBuild, "toolBuild");
        inputs = sortedCopy(inputs, Input::id);
        providers = sortedCopy(providers, Component::id);
        packs = sortedCopy(packs, Component::id);
        validations = sortedCopy(validations, Validation::code);
        mappings = sortedCopy(mappings, Mapping::id);
        appliedSymbols = sortedCopy(appliedSymbols, AppliedSymbol::sortKey);
        appliedTypes = sortedCopy(appliedTypes, AppliedType::sortKey);
        metadata = Collections.unmodifiableMap(new TreeMap<>(metadata));
        Objects.requireNonNull(executionTopology, "executionTopology");
        findings = sortedCopy(findings, Finding::id);
        diagnostics = diagnostics.stream().sorted(Comparator
            .comparing((Diagnostic diagnostic) -> diagnostic.code().id())
            .thenComparing(Diagnostic::message)).toList();
        Objects.requireNonNull(reproducibility, "reproducibility");
        if (!SCHEMA_ID.equals(schemaId)) {
            throw new IllegalArgumentException("Unsupported canonical report schema: " + schemaId);
        }
    }

    public static CanonicalReport create(
            String toolBuild,
            List<Input> inputs,
            List<Component> providers,
            List<Component> packs,
            List<Validation> validations,
            List<Mapping> mappings,
            List<AppliedSymbol> appliedSymbols,
            List<AppliedType> appliedTypes,
            Map<String, String> metadata,
            Optional<ExecutionTopologyReport> executionTopology,
            List<Finding> findings,
            List<Diagnostic> diagnostics,
            Reproducibility reproducibility) {
        return new CanonicalReport(SCHEMA_ID, toolBuild, inputs, providers, packs, validations,
            mappings, appliedSymbols, appliedTypes, metadata, executionTopology, findings,
            diagnostics, reproducibility);
    }

    public String toCanonicalJson() {
        HashMap<String, Object> value = new HashMap<>();
        value.put("schemaId", schemaId);
        value.put("toolBuild", toolBuild);
        value.put("inputs", inputs.stream().map(Input::canonicalValue).toList());
        value.put("providers", providers.stream().map(Component::canonicalValue).toList());
        value.put("packs", packs.stream().map(Component::canonicalValue).toList());
        value.put("validations", validations.stream().map(Validation::canonicalValue).toList());
        value.put("mappings", mappings.stream().map(Mapping::canonicalValue).toList());
        value.put("appliedSymbols", appliedSymbols.stream()
            .map(AppliedSymbol::canonicalValue).toList());
        value.put("appliedTypes", appliedTypes.stream().map(AppliedType::canonicalValue).toList());
        value.put("metadata", metadata);
        value.put("executionTopology", executionTopology
            .map(ExecutionTopologyReport::canonicalValue).orElse(null));
        value.put("findings", findings.stream().map(Finding::canonicalValue).toList());
        value.put("diagnostics", diagnostics.stream().map(CanonicalReport::diagnosticValue).toList());
        value.put("reproducibility", reproducibility.canonicalValue());
        return CanonicalJson.write(value);
    }

    public record Input(String id, String sha256, long length) {
        public Input {
            requireText(id, "input id");
            requireSha256(sha256);
            requireNonNegative(length, "input length");
        }

        Map<String, Object> canonicalValue() {
            return Map.of("id", id, "sha256", sha256, "length", length);
        }
    }

    public record Component(String id, String version, String digest) {
        public Component {
            requireText(id, "component id");
            requireText(version, "component version");
            requireSha256(digest);
        }

        Map<String, Object> canonicalValue() {
            return Map.of("id", id, "version", version, "digest", digest);
        }
    }

    public record Validation(String code, String status, String message, List<Evidence> evidence) {
        public Validation {
            requireText(code, "validation code");
            requireText(status, "validation status");
            requireText(message, "validation message");
            evidence = List.copyOf(evidence);
        }

        Map<String, Object> canonicalValue() {
            return Map.of("code", code, "status", status, "message", message,
                "evidence", evidenceValues(evidence));
        }
    }

    public record Mapping(
            String id,
            SourceRange sourceRange,
            AddressRange targetRange,
            String permissions,
            List<Evidence> evidence) {
        public Mapping {
            requireText(id, "mapping id");
            Objects.requireNonNull(sourceRange, "sourceRange");
            Objects.requireNonNull(targetRange, "targetRange");
            requireText(permissions, "mapping permissions");
            evidence = List.copyOf(evidence);
        }

        Map<String, Object> canonicalValue() {
            return Map.of(
                "id", id,
                "sourceRange", sourceRangeValue(sourceRange),
                "targetRange", addressRangeValue(targetRange),
                "permissions", permissions,
                "evidence", evidenceValues(evidence));
        }
    }

    public record Finding(
            String id,
            String scanner,
            String category,
            String severity,
            Confidence confidence,
            Optional<AddressRange> address,
            String explanation,
            boolean secret) {
        public Finding {
            requireText(id, "finding id");
            requireText(scanner, "finding scanner");
            requireText(category, "finding category");
            requireText(severity, "finding severity");
            Objects.requireNonNull(confidence, "confidence");
            Objects.requireNonNull(address, "address");
            requireText(explanation, "finding explanation");
        }

        Map<String, Object> canonicalValue() {
            HashMap<String, Object> value = new HashMap<>();
            value.put("id", id);
            value.put("scanner", scanner);
            value.put("category", category);
            value.put("severity", severity);
            value.put("confidence", confidence.name());
            value.put("address", address.map(CanonicalReport::addressRangeValue).orElse(null));
            value.put("explanation", explanation);
            value.put("secret", secret);
            return value;
        }
    }

    public record AppliedSymbol(
            String name, String namespace, String addressSpace, long address, String provenance) {
        public AppliedSymbol {
            requireText(name, "symbol name");
            requireText(namespace, "symbol namespace");
            requireText(addressSpace, "symbol address space");
            requireNonNegative(address, "symbol address");
            requireText(provenance, "symbol provenance");
        }

        Map<String, Object> canonicalValue() {
            return Map.of(
                "name", name,
                "namespace", namespace,
                "addressSpace", addressSpace,
                "address", address,
                "provenance", provenance);
        }

        private String sortKey() {
            return namespace + '\0' + name + '\0' + addressSpace + '\0' + Long.toString(address);
        }
    }

    public record AppliedType(String name, String categoryPath, String provenance) {
        public AppliedType {
            requireText(name, "type name");
            requireText(categoryPath, "type category path");
            requireText(provenance, "type provenance");
        }

        Map<String, Object> canonicalValue() {
            return Map.of("name", name, "categoryPath", categoryPath, "provenance", provenance);
        }

        private String sortKey() {
            return categoryPath + '\0' + name;
        }
    }

    public record Reproducibility(boolean redactionEnabled, List<String> enabledEnrichments) {
        public Reproducibility {
            enabledEnrichments = enabledEnrichments.stream().sorted().toList();
        }

        Map<String, Object> canonicalValue() {
            return Map.of(
                "redactionEnabled", redactionEnabled,
                "enabledEnrichments", enabledEnrichments,
                "locale", "en-US",
                "timeZone", "UTC");
        }
    }

    private static Map<String, Object> diagnosticValue(Diagnostic diagnostic) {
        HashMap<String, Object> value = new HashMap<>();
        value.put("code", diagnostic.code().id());
        value.put("severity", diagnostic.severity().name());
        value.put("message", diagnostic.message());
        value.put("sourceRange", diagnostic.sourceRange()
            .map(CanonicalReport::sourceRangeValue).orElse(null));
        return value;
    }

    private static Map<String, Object> sourceRangeValue(SourceRange range) {
        return Map.of("offset", range.offset(), "length", range.length());
    }

    private static Map<String, Object> addressRangeValue(AddressRange range) {
        return Map.of("addressSpace", range.addressSpace(), "start", range.start(), "length", range.length());
    }

    private static List<Map<String, Object>> evidenceValues(List<Evidence> evidence) {
        return evidence.stream().sorted(Comparator.comparing((Evidence item) -> item.kind().name())
            .thenComparing(Evidence::source).thenComparing(Evidence::detail)).map(item -> Map.<String, Object>of(
                "kind", item.kind().name(), "source", item.source(), "detail", item.detail())).toList();
    }

    private static <T> List<T> sortedCopy(List<T> values, java.util.function.Function<T, String> key) {
        return values.stream().sorted(Comparator.comparing(key)).toList();
    }

    private static void requireText(String value, String name) {
        Objects.requireNonNull(value, name);
        if (value.isBlank()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
    }

    private static void requireSha256(String value) {
        Objects.requireNonNull(value, "sha256");
        if (!value.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("Digest must be a lowercase SHA-256 value");
        }
    }

    private static void requireNonNegative(long value, String name) {
        if (value < 0) {
            throw new IllegalArgumentException(name + " must be non-negative");
        }
    }
}
