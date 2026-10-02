package io.github.rezabakhshi.embedra.targets.stm32.catalog;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class Stm32InterruptPlanTest {
    private static final Path CATALOG = Path.of(
        "catalogs/stm32/2026-09-29/curated-catalog.json");

    private static final Path SELECTION = Path.of(
        "catalogs/stm32/2026-09-29/selection.json");

    @TempDir
    Path temporary;

    @Test
    void extractsExactPartInterruptsAndKeepsAmbiguityExplicit() throws Exception {
        Stm32InterruptPlan plan = load(CATALOG);
        assertEquals(53, plan.size());
        Stm32InterruptPlan.Entry f103 = plan.requireEntry("STM32F103C8T6");
        assertTrue(f103.applicable());
        assertEquals("cmsis-device-f1/Include/stm32f103xb.h", f103.header());
        assertEquals("NonMaskableInt_IRQn", f103.interrupts().get(0).name());
        assertTrue(f103.interrupts().stream().anyMatch(
            irq -> irq.name().equals("WWDG_IRQn") && irq.number() == 0));
        assertTrue(f103.interrupts().stream().anyMatch(irq -> irq.number() < 0));
        long applicable = plan.entries().stream().filter(
            Stm32InterruptPlan.Entry::applicable).count();
        assertEquals(51, applicable);
        assertFalse(plan.requireEntry("STM32N657X0H3Q").applicable());
        assertFalse(plan.requireEntry("STM32WL3RKBV6").applicable());
        assertThrows(IllegalArgumentException.class, () -> plan.requireEntry("STM32UNKNOWN"));
        assertThrows(IllegalArgumentException.class,
            () -> new Stm32InterruptPlan.Interrupt("", 0));
        assertThrows(IllegalArgumentException.class,
            () -> new Stm32InterruptPlan.Interrupt("IRQ", -17));
        assertThrows(IllegalArgumentException.class,
            () -> new Stm32InterruptPlan.Interrupt("IRQ", 65536));
        assertThrows(IllegalArgumentException.class,
            () -> new Stm32InterruptPlan.Interrupt("IRQ", Integer.MAX_VALUE));
    }

    @Test
    void digestMismatchIsRejected() throws Exception {
        Path copy = temporary.resolve("catalog.json");
        Files.copy(CATALOG, copy);
        Files.write(copy, " ".getBytes(StandardCharsets.US_ASCII),
            StandardOpenOption.APPEND);
        assertThrows(IOException.class, () -> load(copy));
    }

    private static Stm32InterruptPlan load(Path catalog) throws Exception {
        Stm32CuratedPartIds selection = Stm32CuratedPartIds.load(SELECTION,
            ParserLimits.defaults(), CancellationToken.none());
        return Stm32InterruptPlan.load(catalog, selection, ParserLimits.defaults(),
            CancellationToken.none());
    }
}
