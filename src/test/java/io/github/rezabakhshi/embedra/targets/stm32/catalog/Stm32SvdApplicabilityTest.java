package io.github.rezabakhshi.embedra.targets.stm32.catalog;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class Stm32SvdApplicabilityTest {
    private static final Path SELECTION = Path.of(
        "catalogs/stm32/2026-09-29/selection.json");

    private static final Path APPLICABILITY = Path.of(
        "catalogs/stm32/2026-09-29/svd-applicability.json");

    @TempDir
    Path temporary;

    @Test
    void coversEveryExactPartWithExplicitStatus() throws Exception {
        Stm32SvdApplicability applicability = load(APPLICABILITY);
        assertEquals(53, applicability.size());
        assertEquals(20, applicability.families().size());
        assertEquals(List.of("STM32C031", "STM32F103", "STM32F401", "STM32H503",
            "STM32H735", "STM32WB55_CM0P", "STM32WB55_CM4"),
            applicability.shippedDeviceLines());
        Stm32SvdApplicability.Entry f103 = applicability.requireEntry("STM32F103C8T6");
        assertEquals(Stm32SvdApplicability.Status.EXACT_SVD_SHIPPED, f103.status());
        assertEquals("STM32F103", f103.svdFiles().get(0).deviceName());
        Stm32SvdApplicability.Entry wb55 = applicability.requireEntry("STM32WB55RGV6");
        assertEquals(2, wb55.svdFiles().size());
        Stm32SvdApplicability.Entry absent = applicability.requireEntry("STM32F207ZGT6");
        assertEquals(Stm32SvdApplicability.Status.UNAVAILABLE, absent.status());
        assertTrue(absent.reason().contains("NO_EXACT_SVD"));
        assertTrue(absent.svdFiles().isEmpty());
        Stm32SvdApplicability.Entry deferred = applicability.requireEntry("STM32H573IIK3Q");
        assertEquals(Stm32SvdApplicability.Status.EXACT_SVD_DEFERRED, deferred.status());
        assertThrows(IllegalArgumentException.class,
            () -> applicability.requireEntry("STM32UNKNOWN"));
    }

    @Test
    void wildcardAndUnsafeDeviceLinesAreRejected() {
        assertThrows(IllegalArgumentException.class, () -> new Stm32SvdApplicability.SvdFile(
            "STM32U5Gx", "stm32u5/STM32U5Gx.svd", "0".repeat(64), null));
        assertThrows(IllegalArgumentException.class, () -> new Stm32SvdApplicability.SvdFile(
            "STM32F103", "../secret.svd", "0".repeat(64), null));
        assertThrows(IllegalArgumentException.class, () -> new Stm32SvdApplicability.SvdFile(
            "STM32F103", "stm32f1/STM32F103.svd", "not-a-digest", null));
        assertFalse(new Stm32SvdApplicability.SvdFile("STM32WB55_CM4",
            "stm32wb/STM32WB55_CM4.svd", "0".repeat(64), "CM4").deviceName().isBlank());
    }

    @Test
    void digestMismatchIsRejected() throws Exception {
        Path copy = temporary.resolve("applicability.json");
        Files.copy(APPLICABILITY, copy);
        Files.write(copy, " ".getBytes(java.nio.charset.StandardCharsets.US_ASCII),
            StandardOpenOption.APPEND);
        assertThrows(IOException.class, () -> load(copy));
    }

    private static Stm32SvdApplicability load(Path path) throws Exception {
        return Stm32SvdApplicability.load(path, selection(), ParserLimits.defaults(),
            CancellationToken.none());
    }

    private static Stm32CuratedPartIds selection() throws Exception {
        return Stm32CuratedPartIds.load(SELECTION, ParserLimits.defaults(),
            CancellationToken.none());
    }
}
