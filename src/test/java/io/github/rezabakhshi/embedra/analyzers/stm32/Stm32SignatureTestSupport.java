package io.github.rezabakhshi.embedra.analyzers.stm32;

import io.github.rezabakhshi.embedra.pack.PackFile;
import io.github.rezabakhshi.embedra.pack.PackIntegrity;
import io.github.rezabakhshi.embedra.pack.PackManifest;
import io.github.rezabakhshi.embedra.pack.PackProvenance;
import io.github.rezabakhshi.embedra.pack.PackVersion;
import io.github.rezabakhshi.embedra.pack.RedistributionStatus;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Optional;

/** Shared synthetic-pack builders for the STM32 signature tests. */
final class Stm32SignatureTestSupport {
    static final String COMPILER = "arm-none-eabi-gcc (15:13.2.rel1-2) 13.2.1 20231009";

    static final String OPTIMIZATION = "-Os";

    static final String SOURCE_SHA =
        "9f64a747e1b97f131fabb6b447296c9b6f0201e79fb3c5356e6c77e89b6a806a";

    private Stm32SignatureTestSupport() {
    }

    static Stm32LibrarySignature signature(String id, String functionName,
            byte[] pattern, byte[] mask) {
        return new Stm32LibrarySignature(id, "stm32f1xx-hal", "stm32f1xx-hal", functionName,
            "STM32F1", COMPILER, OPTIMIZATION,
            "Drivers/STM32F1xx_HAL_Driver/Src/stm32f1xx_hal.c", SOURCE_SHA, pattern, mask);
    }

    static Stm32SignaturePack pack(Stm32LibrarySignature... signatures) {
        PackFile file = new PackFile("signatures.json", 4, SOURCE_SHA);
        try {
            PackManifest manifest = new PackManifest(PackManifest.SCHEMA_ID,
                Stm32SignaturePackLoader.PACK_ID, PackVersion.parse("1.0.0"),
                PackIntegrity.contentDigest(List.of(file)), List.of("STM32F1"),
                new PackProvenance(
                    new URI("https://github.com/STMicroelectronics/STM32CubeF1"),
                    Stm32SignaturePackLoader.SOURCE_PACKAGE,
                    Stm32SignaturePackLoader.LICENSE, "test", RedistributionStatus.ALLOWED),
                List.of(file));
            return new Stm32SignaturePack(manifest, List.of(signatures));
        }
        catch (URISyntaxException exception) {
            throw new IllegalStateException(exception);
        }
    }

    static Stm32SignatureContext context(Optional<String> compiler,
            Optional<String> optimization, String family, Stm32FunctionBytes... functions) {
        return new Stm32SignatureContext("STM32F103C8T6", family, compiler, optimization,
            List.of(functions));
    }

    static byte[] allSpecifiedMask(int length) {
        byte[] mask = new byte[length];
        java.util.Arrays.fill(mask, (byte) 0xff);
        return mask;
    }
}
