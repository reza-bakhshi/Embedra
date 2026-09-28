package io.github.rezabakhshi.embedra.targets.esp.catalog;

import io.github.rezabakhshi.embedra.core.catalog.CatalogSource;
import io.github.rezabakhshi.embedra.core.catalog.DeviceCatalogEntry;
import io.github.rezabakhshi.embedra.core.catalog.DeviceCatalogSnapshot;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Predicate;

/** Validated offline ESP product catalog and non-guessing exact-variant resolver. */
public final class EspDeviceCatalog {
    public static final String SCHEMA_ID = "urn:embedra:schema:esp-device-catalog:1";

    private final String catalogId;

    private final String snapshotDate;

    private final String generator;

    private final String sourceFactsSha256;

    private final List<EspCatalogSource> sources;

    private final List<EspCatalogRecord> records;

    private final Map<String, List<EspCatalogRecord>> byExactPart;

    EspDeviceCatalog(
            String schemaId,
            String catalogId,
            String snapshotDate,
            String generator,
            String sourceFactsSha256,
            List<EspCatalogSource> sources,
            List<EspCatalogRecord> records) {
        if (!SCHEMA_ID.equals(schemaId)) {
            throw new IllegalArgumentException("Unsupported ESP catalog schema: " + schemaId);
        }
        this.catalogId = require(catalogId, "catalogId");
        this.snapshotDate = require(snapshotDate, "snapshotDate");
        this.generator = require(generator, "generator");
        this.sourceFactsSha256 = require(sourceFactsSha256, "sourceFactsSha256");
        if (!sourceFactsSha256.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("Source-facts SHA-256 is invalid");
        }
        this.sources = List.copyOf(sources);
        this.records = records.stream().sorted(Comparator.comparing(EspCatalogRecord::recordId))
            .toList();
        if (this.sources.isEmpty() || this.records.isEmpty()) {
            throw new IllegalArgumentException("ESP catalog sources and records are required");
        }
        validateRelationships(this.records);
        byExactPart = index(this.records);
    }

    public String catalogId() {
        return catalogId;
    }

    public String snapshotDate() {
        return snapshotDate;
    }

    public String generator() {
        return generator;
    }

    public String sourceFactsSha256() {
        return sourceFactsSha256;
    }

    public List<EspCatalogSource> sources() {
        return sources;
    }

    public List<EspCatalogRecord> records() {
        return records;
    }

    public List<EspCatalogRecord> silicon() {
        return records(EspCatalogEntityKind.SILICON);
    }

    public List<EspCatalogRecord> modules() {
        return records(EspCatalogEntityKind.MODULE);
    }

    public List<EspCatalogRecord> boards() {
        return records(EspCatalogEntityKind.BOARD);
    }

    /** Projects exact silicon into the shared deterministic device-catalog contract. */
    public DeviceCatalogSnapshot deviceSnapshot() {
        CatalogSource source = new CatalogSource(
            "Espressif official product catalog plus ESP-IDF",
            sourceFactsSha256,
            "Apache-2.0 AND LicenseRef-Espressif-Public-Product-Facts",
            "Normalized source facts; generator " + generator);
        List<DeviceCatalogEntry> devices = silicon().stream().map(record ->
            new DeviceCatalogEntry(
                record.recordId(), "Espressif Systems", "ESP32", record.series(),
                record.exactPart(), record.packageName(), Map.ofEntries(
                    Map.entry("applicationCoreCount",
                        Integer.toString(record.applicationCoreCount())),
                    Map.entry("auxiliaryProcessors",
                        String.join(",", record.auxiliaryProcessors())),
                    Map.entry("embeddedFlashMb", record.embeddedFlashMb()),
                    Map.entry("embeddedPsramMb", record.embeddedPsramMb()),
                    Map.entry("firmwareChipId", record.firmwareChipId()),
                    Map.entry("isa", record.isa().name()),
                    Map.entry("lifecycle", record.lifecycle()),
                    Map.entry("peripheralCapabilities",
                        String.join(",", record.peripheralCapabilities())),
                    Map.entry("romIdentity", record.romIdentity()),
                    Map.entry("securityCapabilities",
                        String.join(",", record.securityCapabilities())),
                    Map.entry("siliconRevision", record.siliconRevision()),
                    Map.entry("topologyEvidence", record.topologyEvidence())),
                record.supportStates())).toList();
        return DeviceCatalogSnapshot.create(catalogId, source, devices);
    }

    public EspCatalogRecord requireExactPart(String exactPart) {
        EspCatalogResolution resolution = exactLookup(exactPart);
        return resolution.requireExact();
    }

    /** Requires an exact silicon identity and rejects module or board names. */
    public EspCatalogRecord requireExactSilicon(String exactPart) {
        return resolveSilicon(exactPart).requireExact();
    }

    /** Resolves only exact silicon records. Product profiles are never candidates. */
    public EspCatalogResolution resolveSilicon(String query) {
        return resolve(query, record -> record.kind() == EspCatalogEntityKind.SILICON);
    }

    /** Resolves only module profiles without treating them as processor identities. */
    public EspCatalogResolution resolveModule(String query) {
        return resolve(query, record -> record.kind() == EspCatalogEntityKind.MODULE);
    }

    /** Resolves only board profiles without treating them as processor identities. */
    public EspCatalogResolution resolveBoard(String query) {
        return resolve(query, record -> record.kind() == EspCatalogEntityKind.BOARD);
    }

    /** Resolves module and board profiles while excluding exact silicon records. */
    public EspCatalogResolution resolveProfile(String query) {
        return resolve(query, record -> record.kind() != EspCatalogEntityKind.SILICON);
    }

    /** Returns the exact silicon candidates explicitly referenced by a profile. */
    public List<EspCatalogRecord> compatibleSilicon(EspCatalogRecord profile) {
        Objects.requireNonNull(profile, "profile");
        if (profile.kind() == EspCatalogEntityKind.SILICON) {
            throw new IllegalArgumentException("Silicon records are not product profiles");
        }
        Map<String, EspCatalogRecord> siliconById = silicon().stream().collect(
            java.util.stream.Collectors.toUnmodifiableMap(EspCatalogRecord::recordId,
                record -> record));
        return profile.siliconRecordIds().stream().map(siliconById::get)
            .sorted(Comparator.comparing(EspCatalogRecord::recordId)).toList();
    }

    /** Returns all module and board profiles that explicitly reference exact silicon. */
    public List<EspCatalogRecord> profilesForSilicon(String exactPart) {
        String siliconId = requireExactSilicon(exactPart).recordId();
        return records.stream().filter(record ->
            record.kind() != EspCatalogEntityKind.SILICON
                && record.siliconRecordIds().contains(siliconId)).toList();
    }

    public EspCatalogResolution resolve(String query) {
        return resolve(query, ignored -> true);
    }

    private EspCatalogResolution resolve(String query, Predicate<EspCatalogRecord> filter) {
        require(query, "query");
        Objects.requireNonNull(filter, "filter");
        List<EspCatalogRecord> exactCandidates = byExactPart.getOrDefault(
            normalize(query), List.of()).stream().filter(filter).toList();
        EspCatalogResolution exact = resolution(query, exactCandidates);
        if (exact.status() != EspCatalogResolutionStatus.UNKNOWN) {
            return exact;
        }
        String normalized = normalize(query);
        List<EspCatalogRecord> candidates = records.stream()
            .filter(filter)
            .filter(record -> normalize(record.exactPart()).startsWith(normalized + "-"))
            .toList();
        return resolution(query, candidates);
    }

    private EspCatalogResolution exactLookup(String query) {
        require(query, "query");
        List<EspCatalogRecord> candidates = byExactPart.getOrDefault(normalize(query), List.of());
        return resolution(query, candidates);
    }

    private static EspCatalogResolution resolution(
            String query, List<EspCatalogRecord> candidates) {
        if (candidates.size() == 1) {
            return new EspCatalogResolution(EspCatalogResolutionStatus.EXACT, query, candidates);
        }
        if (candidates.size() > 1) {
            return new EspCatalogResolution(EspCatalogResolutionStatus.AMBIGUOUS, query, candidates);
        }
        return new EspCatalogResolution(EspCatalogResolutionStatus.UNKNOWN, query, List.of());
    }

    private List<EspCatalogRecord> records(EspCatalogEntityKind kind) {
        return records.stream().filter(record -> record.kind() == kind).toList();
    }

    private static void validateRelationships(List<EspCatalogRecord> records) {
        Set<String> ids = new HashSet<>();
        Set<String> siliconIds = new HashSet<>();
        for (EspCatalogRecord record : records) {
            if (!ids.add(record.recordId())) {
                throw new IllegalArgumentException("Duplicate ESP catalog record ID");
            }
            if (record.kind() == EspCatalogEntityKind.SILICON) {
                siliconIds.add(record.recordId());
            }
        }
        for (EspCatalogRecord record : records) {
            if (!siliconIds.containsAll(record.siliconRecordIds())) {
                throw new IllegalArgumentException("Profile references unknown silicon");
            }
        }
    }

    private static Map<String, List<EspCatalogRecord>> index(List<EspCatalogRecord> records) {
        Map<String, List<EspCatalogRecord>> result = new HashMap<>();
        for (EspCatalogRecord record : records) {
            result.computeIfAbsent(normalize(record.exactPart()), ignored -> new ArrayList<>())
                .add(record);
        }
        result.replaceAll((ignored, values) -> List.copyOf(values));
        return Map.copyOf(result);
    }

    private static String normalize(String value) {
        return value.toUpperCase(Locale.ROOT);
    }

    private static String require(String value, String name) {
        Objects.requireNonNull(value, name);
        if (value.isBlank()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
        return value;
    }
}
