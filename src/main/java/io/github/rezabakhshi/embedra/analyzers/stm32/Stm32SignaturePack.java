package io.github.rezabakhshi.embedra.analyzers.stm32;

import io.github.rezabakhshi.embedra.pack.PackManifest;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;

/** Validated signature payload associated with an ordinary Embedra pack manifest. */
public record Stm32SignaturePack(PackManifest manifest, List<Stm32LibrarySignature> signatures) {
    public Stm32SignaturePack {
        Objects.requireNonNull(manifest, "manifest");
        signatures = signatures.stream()
            .sorted(Comparator.comparing(Stm32LibrarySignature::signatureId)).toList();
        if (signatures.isEmpty()
            || new HashSet<>(signatures.stream().map(Stm32LibrarySignature::signatureId).toList())
                .size() != signatures.size()) {
            throw new IllegalArgumentException("Signature IDs must be non-empty and unique");
        }
        if (signatures.stream().anyMatch(signature ->
                !manifest.supportedDevices().contains(signature.family()))) {
            throw new IllegalArgumentException("Signature family is absent from the pack manifest");
        }
    }

    public String identity() {
        return manifest.packId() + "@" + manifest.version();
    }
}
