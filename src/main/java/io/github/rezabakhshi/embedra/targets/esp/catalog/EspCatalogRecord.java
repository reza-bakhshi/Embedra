package io.github.rezabakhshi.embedra.targets.esp.catalog;

import io.github.rezabakhshi.embedra.core.catalog.SupportState;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

/** One exact silicon part or module/board product profile. */
public record EspCatalogRecord(
        String recordId,
        EspCatalogEntityKind kind,
        String series,
        String exactPart,
        String packageName,
        EspCpuIsa isa,
        int applicationCoreCount,
        List<String> auxiliaryProcessors,
        String embeddedFlashMb,
        String embeddedPsramMb,
        String lifecycle,
        String siliconRevision,
        String firmwareChipId,
        String romIdentity,
        String topologyEvidence,
        List<String> socCapabilityMacros,
        List<String> peripheralCapabilities,
        List<String> securityCapabilities,
        List<String> siliconRecordIds,
        Map<String, SupportState> supportStates) {
    public EspCatalogRecord {
        require(recordId, "recordId");
        Objects.requireNonNull(kind, "kind");
        require(series, "series");
        require(exactPart, "exactPart");
        require(packageName, "packageName");
        Objects.requireNonNull(isa, "isa");
        require(embeddedFlashMb, "embeddedFlashMb");
        require(embeddedPsramMb, "embeddedPsramMb");
        require(lifecycle, "lifecycle");
        require(siliconRevision, "siliconRevision");
        require(firmwareChipId, "firmwareChipId");
        require(romIdentity, "romIdentity");
        require(topologyEvidence, "topologyEvidence");
        auxiliaryProcessors = List.copyOf(auxiliaryProcessors);
        socCapabilityMacros = List.copyOf(socCapabilityMacros);
        peripheralCapabilities = List.copyOf(peripheralCapabilities);
        securityCapabilities = List.copyOf(securityCapabilities);
        siliconRecordIds = List.copyOf(siliconRecordIds);
        supportStates = Collections.unmodifiableMap(new TreeMap<>(supportStates));
        if (supportStates.isEmpty() || applicationCoreCount < 0) {
            throw new IllegalArgumentException("Catalog record state and core count are invalid");
        }
        if (kind == EspCatalogEntityKind.SILICON
            && (isa == EspCpuIsa.PROFILE || applicationCoreCount == 0
                || !siliconRecordIds.isEmpty())) {
            throw new IllegalArgumentException("Silicon must carry executable topology only");
        }
        if (kind != EspCatalogEntityKind.SILICON
            && (isa != EspCpuIsa.PROFILE || applicationCoreCount != 0
                || siliconRecordIds.isEmpty())) {
            throw new IllegalArgumentException("Profiles must reference exact silicon records");
        }
    }

    private static void require(String value, String name) {
        Objects.requireNonNull(value, name);
        if (value.isBlank()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
    }
}
