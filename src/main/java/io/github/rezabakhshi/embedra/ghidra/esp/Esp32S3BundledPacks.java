package io.github.rezabakhshi.embedra.ghidra.esp;

import generic.jar.ResourceFile;
import ghidra.framework.Application;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.pack.EspPeripheralPack;
import io.github.rezabakhshi.embedra.pack.EspRomSymbolPack;
import io.github.rezabakhshi.embedra.pack.EspSvdPack;
import io.github.rezabakhshi.embedra.pack.EspTargetPackLoader;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;

/** Resolves integrity-checked packs from either an installed module or test tree. */
record Esp32S3BundledPacks(
        EspRomSymbolPack rom,
        EspPeripheralPack peripherals,
        Optional<EspSvdPack> svd) {
    static Esp32S3BundledPacks load(CancellationToken token)
            throws IOException, DiagnosticException {
        return load("esp32s3", true, token);
    }

    static Esp32S3BundledPacks load(String deviceId, CancellationToken token)
            throws IOException, DiagnosticException {
        return load(deviceId, true, token);
    }

    static Esp32S3BundledPacks load(String deviceId, boolean hasSvd,
            CancellationToken token) throws IOException, DiagnosticException {
        ParserLimits limits = ParserLimits.defaults();
        return new Esp32S3BundledPacks(
            EspTargetPackLoader.loadRom(packDirectory("espressif." + deviceId + ".rom"),
                deviceId, limits, token),
            EspTargetPackLoader.loadPeripherals(packDirectory(
                "espressif." + deviceId + ".peripherals"), deviceId, limits, token),
            hasSvd ? Optional.of(EspTargetPackLoader.loadSvd(
                packDirectory("espressif." + deviceId + ".svd"), deviceId, limits, token))
                : Optional.empty());
    }

    private static Path packDirectory(String packId) throws IOException {
        String relative = "packs/" + packId + "/1.0.0/pack.json";
        ResourceFile module = Application.getModuleContainingClass(
            EspApplicationImageLoader.class);
        if (module != null) {
            ResourceFile manifest = new ResourceFile(module, relative);
            if (manifest.isFile()) {
                File extracted = manifest.getFile(true);
                return extracted.toPath().getParent();
            }
        }
        String project = System.getProperty("embedra.projectDir", "");
        if (!project.isBlank()) {
            Path directory = Path.of(project, "packs", packId, "1.0.0");
            if (Files.isRegularFile(directory.resolve("pack.json"))) {
                return directory;
            }
        }
        throw new IOException("Bundled ESP pack is unavailable: " + packId);
    }
}
