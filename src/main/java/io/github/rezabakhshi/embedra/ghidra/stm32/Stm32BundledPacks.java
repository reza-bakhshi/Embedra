package io.github.rezabakhshi.embedra.ghidra.stm32;

import generic.jar.ResourceFile;
import ghidra.framework.Application;
import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.pack.Stm32SvdPack;
import io.github.rezabakhshi.embedra.pack.Stm32SvdPackLoader;
import io.github.rezabakhshi.embedra.targets.stm32.catalog.Stm32SvdApplicability;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Resolves integrity-checked STM32 SVD packs from the installed module or the
 * source tree. Only reviewed shipped applicability entries materialize packs: a
 * shipped entry whose pack is missing fails closed, and a deferred or
 * unavailable entry always yields no pack even if a matching directory exists.
 */
public final class Stm32BundledPacks {
    public static final String VERSION_DIRECTORY = "1.0.0";

    private final Map<String, Stm32SvdPack> byDevice;

    private Stm32BundledPacks(Map<String, Stm32SvdPack> byDevice) {
        this.byDevice = Map.copyOf(byDevice);
    }

    /** Loads every pack required by one shipped applicability entry, in device-line order. */
    public static Stm32BundledPacks load(Stm32SvdApplicability.Entry entry,
            ParserLimits limits, CancellationToken token)
            throws IOException, DiagnosticException {
        Map<String, Stm32SvdPack> packs = new LinkedHashMap<>();
        if (entry.status() != Stm32SvdApplicability.Status.EXACT_SVD_SHIPPED) {
            return new Stm32BundledPacks(packs);
        }
        for (Stm32SvdApplicability.SvdFile file : entry.svdFiles()) {
            Optional<Path> directory = packDirectory(file.deviceName());
            if (directory.isEmpty()) {
                throw new IOException("Shipped STM32 SVD pack is unavailable: "
                    + file.deviceName());
            }
            Stm32SvdPack pack = Stm32SvdPackLoader.load(directory.get(), limits, token);
            if (!pack.device().name().equals(file.deviceName())
                || !pack.sourceFile().equals(file.path())
                || !pack.sourceFileSha256().equals(file.sha256())
                || !java.util.Objects.equals(pack.cpu(), file.cpu())
                || !pack.manifest().supportedDevices().contains(entry.exactPart())) {
                throw new IOException(
                    "STM32 SVD pack identity or source provenance does not match applicability");
            }
            packs.put(file.deviceName(), pack);
        }
        return new Stm32BundledPacks(packs);
    }

    public Optional<Stm32SvdPack> forDevice(String deviceName) {
        return Optional.ofNullable(byDevice.get(deviceName));
    }

    public Map<String, Stm32SvdPack> packs() {
        return byDevice;
    }

    private static Optional<Path> packDirectory(String deviceName) {
        String packId = "stm32." + deviceName.toLowerCase(java.util.Locale.ROOT)
            .replace('_', '-') + ".svd";
        String relative = "packs/" + packId + "/" + VERSION_DIRECTORY + "/pack.json";
        ResourceFile module = Application.getModuleContainingClass(
            Stm32BundledPacks.class);
        if (module != null) {
            ResourceFile manifest = new ResourceFile(module, relative);
            if (manifest.isFile()) {
                File extracted = manifest.getFile(true);
                return Optional.of(extracted.toPath().getParent());
            }
        }
        String project = System.getProperty("embedra.projectDir", "");
        if (!project.isBlank()) {
            Path directory = Path.of(project, "packs", packId, VERSION_DIRECTORY);
            if (Files.isRegularFile(directory.resolve("pack.json"))) {
                return Optional.of(directory);
            }
        }
        return Optional.empty();
    }
}
