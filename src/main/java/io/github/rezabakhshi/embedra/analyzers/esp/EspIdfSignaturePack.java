package io.github.rezabakhshi.embedra.analyzers.esp;

import io.github.rezabakhshi.embedra.pack.PackManifest;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;

/** Validated signature payload associated with an ordinary Embedra pack manifest. */
public record EspIdfSignaturePack(
        PackManifest manifest, List<EspLibrarySignature> signatures) {
    public EspIdfSignaturePack {
        Objects.requireNonNull(manifest, "manifest");
        signatures = signatures.stream()
            .sorted(Comparator.comparing(EspLibrarySignature::signatureId)).toList();
        if (signatures.isEmpty()
            || new HashSet<>(signatures.stream().map(EspLibrarySignature::signatureId).toList())
                .size() != signatures.size()) {
            throw new IllegalArgumentException("Signature IDs must be non-empty and unique");
        }
        if (signatures.stream().anyMatch(signature ->
                !manifest.supportedDevices().contains(signature.deviceId()))) {
            throw new IllegalArgumentException("Signature target is absent from pack manifest");
        }
    }

    public String identity() {
        return manifest.packId() + "@" + manifest.version();
    }
}
