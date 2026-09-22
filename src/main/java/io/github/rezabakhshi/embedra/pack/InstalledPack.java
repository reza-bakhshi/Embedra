package io.github.rezabakhshi.embedra.pack;

import java.nio.file.Path;
import java.util.Objects;

/** Verified pack at its local repository location. */
public record InstalledPack(PackManifest manifest, Path directory) {
    public InstalledPack {
        Objects.requireNonNull(manifest, "manifest");
        directory = Objects.requireNonNull(directory, "directory").toAbsolutePath().normalize();
    }
}
