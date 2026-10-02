package io.github.rezabakhshi.embedra.analyzers.stm32;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.github.rezabakhshi.embedra.pack.PackFile;
import io.github.rezabakhshi.embedra.pack.PackIntegrity;
import io.github.rezabakhshi.embedra.pack.PackManifest;
import io.github.rezabakhshi.embedra.pack.PackProvenance;
import io.github.rezabakhshi.embedra.pack.PackVersion;
import io.github.rezabakhshi.embedra.pack.RedistributionStatus;
import java.net.URI;
import java.util.List;
import org.junit.jupiter.api.Test;

class Stm32SignaturePackTest {
    private static final byte[] PATTERN =
        {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte) 0x88};

    @Test
    void rejectsDuplicateIdentifiersAndForeignFamilies() throws Exception {
        Stm32LibrarySignature first = Stm32SignatureTestSupport.signature("same", "One",
            PATTERN, Stm32SignatureTestSupport.allSpecifiedMask(PATTERN.length));
        assertThrows(IllegalArgumentException.class, () -> Stm32SignatureTestSupport.pack(first, first));

        PackFile file = new PackFile("signatures.json", 4, Stm32SignatureTestSupport.SOURCE_SHA);
        PackManifest manifest = new PackManifest(PackManifest.SCHEMA_ID,
            Stm32SignaturePackLoader.PACK_ID, PackVersion.parse("1.0.0"),
            PackIntegrity.contentDigest(List.of(file)), List.of("STM32F4"),
            new PackProvenance(new URI("https://example.invalid/source"), "rev", "MIT",
                "test", RedistributionStatus.ALLOWED), List.of(file));
        assertThrows(IllegalArgumentException.class,
            () -> new Stm32SignaturePack(manifest, List.of(first)));
        assertThrows(IllegalArgumentException.class,
            () -> new Stm32SignaturePack(manifest, List.of()));
    }

    @Test
    void reportsStableIdentity() {
        Stm32LibrarySignature first = Stm32SignatureTestSupport.signature("stm32f1.hal.One.Os",
            "One", PATTERN, Stm32SignatureTestSupport.allSpecifiedMask(PATTERN.length));
        assertEquals("stm32.stm32f1.signatures@1.0.0",
            Stm32SignatureTestSupport.pack(first).identity());
    }
}
