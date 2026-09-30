package io.github.rezabakhshi.embedra.core.stm32.input;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticCode;
import io.github.rezabakhshi.embedra.core.diagnostic.DiagnosticException;
import io.github.rezabakhshi.embedra.targets.stm32.catalog.Stm32CuratedPartIds;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class Stm32RawBinPlanTest {
    private static final Path SELECTION = Path.of(
        "catalogs/stm32/2026-09-29/selection.json");

    private static final long END = 0x1_0000_0000L;

    @TempDir
    Path temporary;

    @Test
    void selectionTokenAcceptsAllFiftyThreeExactIdsAndRejectsFamilyNames() throws Exception {
        Stm32CuratedPartIds parts = load();
        assertEquals(53, parts.size());
        assertTrue(parts.containsExactPart("STM32F103C8T6"));
        assertTrue(parts.containsExactPart("STM32N657X0H3Q"));
        assertFalse(parts.containsExactPart("STM32F103"));
        assertFalse(parts.containsExactPart("stm32f103c8t6"));
    }

    @Test
    void selectionTokenRejectsMissingOversizedTamperedAndCancelledSources() throws Exception {
        assertThrows(IOException.class, () -> Stm32CuratedPartIds.load(
            temporary.resolve("missing.json"), ParserLimits.defaults(), CancellationToken.none()));
        ParserLimits tiny = new ParserLimits(10, 10, 10, 1, 1, Duration.ofSeconds(1));
        assertThrows(IOException.class, () -> Stm32CuratedPartIds.load(
            SELECTION, tiny, CancellationToken.none()));
        ParserLimits allocationLimit = new ParserLimits(1_000_000, 10, 10, 1, 1,
            Duration.ofSeconds(1));
        assertThrows(IOException.class, () -> Stm32CuratedPartIds.load(
            SELECTION, allocationLimit, CancellationToken.none()));
        Path modified = temporary.resolve("selection.json");
        byte[] bytes = Files.readAllBytes(SELECTION);
        bytes[0] ^= 1;
        Files.write(modified, bytes);
        assertThrows(IOException.class, () -> Stm32CuratedPartIds.load(
            modified, ParserLimits.defaults(), CancellationToken.none()));
        DiagnosticException cancelled = assertThrows(DiagnosticException.class,
            () -> Stm32CuratedPartIds.load(SELECTION, ParserLimits.defaults(), () -> true));
        assertEquals(DiagnosticCode.CANCELLED, cancelled.diagnostic().code());
    }

    @Test
    void explicitPlanRequiresSelectedPartAndSpecifiedBoundedBase() throws Exception {
        Stm32CuratedPartIds parts = load();
        ParserLimits limits = ParserLimits.defaults();
        Stm32RawBinPlan flash = Stm32RawBinPlan.explicit(
            "STM32F103C8T6", 0x08000000L, 276, parts, limits);
        assertEquals("STM32F103C8T6", flash.exactPart());
        assertEquals(0x08000000L, flash.baseAddress());
        assertEquals(276, flash.length());
        assertEquals(END - 1, Stm32RawBinPlan.explicit(
            "STM32F103C8T6", END - 1, 1, parts, limits).baseAddress());
        assertThrows(IllegalArgumentException.class,
            () -> Stm32RawBinPlan.explicit("STM32F103", 0, 1, parts, limits));
        assertThrows(IllegalArgumentException.class,
            () -> Stm32RawBinPlan.explicit("STM32F103C8T6", 0, 0, parts, limits));
        assertThrows(IllegalArgumentException.class,
            () -> Stm32RawBinPlan.explicit("STM32F103C8T6", 0,
                limits.maxInputBytes() + 1, parts, limits));
        ParserLimits extractionLimit = new ParserLimits(100, 100, 1, 10, 4,
            Duration.ofSeconds(1));
        assertThrows(IllegalArgumentException.class,
            () -> Stm32RawBinPlan.explicit("STM32F103C8T6", 0, 2,
                parts, extractionLimit));
        assertThrows(IllegalArgumentException.class,
            () -> Stm32RawBinPlan.explicit("STM32F103C8T6", -1, 1, parts, limits));
        assertThrows(IllegalArgumentException.class,
            () -> Stm32RawBinPlan.explicit("STM32F103C8T6", END, 1, parts, limits));
        assertThrows(IllegalArgumentException.class,
            () -> Stm32RawBinPlan.explicit("STM32F103C8T6", END - 1, 2,
                parts, limits));
    }

    private static Stm32CuratedPartIds load() throws IOException, DiagnosticException {
        return Stm32CuratedPartIds.load(SELECTION, ParserLimits.defaults(),
            CancellationToken.none());
    }
}
