package io.github.rezabakhshi.embedra.targets.stm32.vector;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.rezabakhshi.embedra.core.CancellationToken;
import io.github.rezabakhshi.embedra.core.ParserLimits;
import io.github.rezabakhshi.embedra.targets.stm32.catalog.Stm32CuratedPartIds;
import io.github.rezabakhshi.embedra.targets.stm32.catalog.Stm32InterruptPlan;
import io.github.rezabakhshi.embedra.targets.stm32.memory.Stm32MemoryPlanner;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.Test;

class Stm32VectorPlannerTest {
    private static final String PART = "STM32F103C8T6";

    private static final long BASE = 0x0800_0000L;

    private static final long LENGTH = 0x1000L;

    @Test
    void explicitCoreExceptionTableHasCanonicalNamesNumbersAndSlots() {
        assertEquals(9, Stm32CoreException.table().size());
        assertEquals("NonMaskableInt", Stm32CoreException.NON_MASKABLE_INT.handlerName());
        assertEquals(-14, Stm32CoreException.NON_MASKABLE_INT.vectorNumber());
        assertEquals(2, Stm32CoreException.NON_MASKABLE_INT.slot());
        assertEquals("MemManage", Stm32CoreException.MEM_MANAGE.handlerName());
        assertEquals("SysTick", Stm32CoreException.SYS_TICK.handlerName());
        assertEquals(Stm32CoreException.SYS_TICK, Stm32CoreException.forVectorNumber(-1).orElseThrow());
        assertEquals(Stm32CoreException.SV_CALL, Stm32CoreException.forSlot(11).orElseThrow());
        assertTrue(Stm32CoreException.forVectorNumber(0).isEmpty());
        assertTrue(Stm32CoreException.forSlot(13).isEmpty());
        assertEquals(-15, Stm32CoreException.RESET_VECTOR_NUMBER);
    }

    @Test
    void resolvesResetCoreAndDeviceHandlersFromConfirmedWords() {
        Stm32InterruptPlan.Entry entry = entry("MAPPED_SINGLE", List.of(
            interrupt("NonMaskableInt_IRQn", -14),
            interrupt("HardFault_IRQn", -13),
            interrupt("WWDG_IRQn", 0),
            interrupt("PVD_IRQn", 1)));
        List<Long> words = words(18);
        words.set(1, BASE | 1L);
        words.set(2, BASE + 0x20L | 1L);
        words.set(3, BASE + 0x30L | 1L);
        words.set(16, BASE + 0x40L | 1L);
        words.set(17, BASE + 0x50L | 1L);

        Stm32VectorPlan plan = Stm32VectorPlanner.plan(entry, words, BASE, BASE, LENGTH);

        assertTrue(plan.applicable());
        assertEquals("CONFIRMED", plan.reason());
        assertEquals(BASE, plan.tableAddress().orElseThrow());
        assertEquals(PART, plan.exactPart());
        Stm32VectorPlan.Slot reset = slot(plan, 1);
        assertEquals(Stm32VectorPlan.Kind.RESET, reset.kind());
        assertEquals("Reset", reset.name());
        assertEquals(PART + "_Reset", reset.label());
        assertEquals(BASE, reset.handlerAddress());
        assertEquals(Stm32VectorPlan.HandlerStatus.RESOLVED, reset.handlerStatus());
        Stm32VectorPlan.Slot nmi = slot(plan, 2);
        assertEquals(Stm32VectorPlan.Kind.CORE_EXCEPTION, nmi.kind());
        assertEquals("NonMaskableInt", nmi.name());
        assertEquals(BASE + 0x20L, nmi.handlerAddress());
        Stm32VectorPlan.Slot wwdg = slot(plan, 16);
        assertEquals(Stm32VectorPlan.Kind.DEVICE_IRQ, wwdg.kind());
        assertEquals(0, wwdg.vectorNumber());
        assertEquals("WWDG_IRQn", wwdg.name());
        assertEquals(PART + "_WWDG_IRQn", wwdg.label());
        assertEquals(BASE + 0x40L, wwdg.handlerAddress());
        assertEquals(BASE + 0x50L, slot(plan, 17).handlerAddress());
        assertEquals(Stm32VectorPlan.Kind.STACK_POINTER, slot(plan, 0).kind());
        assertEquals(Stm32VectorPlan.HandlerStatus.NOT_A_HANDLER, slot(plan, 0).handlerStatus());
    }

    @Test
    void canonicalizesStandardCoreExceptionNamesFromPinnedList() {
        Stm32InterruptPlan.Entry entry = entry("MAPPED_SINGLE",
            List.of(interrupt("MemoryManagement_IRQn", -12)));
        Stm32VectorPlan plan = Stm32VectorPlanner.plan(entry, words(16), BASE, BASE, LENGTH);
        Stm32VectorPlan.Slot slot = slot(plan, 4);
        assertEquals(Stm32VectorPlan.Kind.CORE_EXCEPTION, slot.kind());
        assertEquals("MemManage", slot.name());
        assertEquals(PART + "_MemManage", slot.label());
    }

    @Test
    void preservesUnlistedVendorCoreExceptionFromPinnedName() {
        Stm32InterruptPlan.Entry entry = entry("MAPPED_SINGLE",
            List.of(interrupt("SecureFault_IRQn", -9)));
        Stm32VectorPlan plan = Stm32VectorPlanner.plan(entry, words(16), BASE, BASE, LENGTH);
        Stm32VectorPlan.Slot slot = slot(plan, 7);
        assertEquals(Stm32VectorPlan.Kind.CORE_EXCEPTION, slot.kind());
        assertEquals("SecureFault_IRQn", slot.name());
        assertTrue(plan.diagnostics().stream().anyMatch(diagnostic ->
            diagnostic.code().equals("UNLISTED_CORE_EXCEPTION")));
    }

    @Test
    void alwaysCreatesArchitecturalResetEvenWhenNotPinned() {
        Stm32InterruptPlan.Entry entry = entry("MAPPED_SINGLE", List.of(interrupt("WWDG_IRQn", 0)));
        Stm32VectorPlan plan = Stm32VectorPlanner.plan(entry, words(17), BASE, BASE, LENGTH);
        assertEquals(Stm32VectorPlan.Kind.RESET, slot(plan, 1).kind());
        assertTrue(plan.diagnostics().stream().anyMatch(diagnostic ->
            diagnostic.code().equals("CORE_EXCEPTION_ABSENT")));
    }

    @Test
    void reservedSlotsPreserveUnknownWordsWithoutFabricatingNames() {
        List<Long> words = words(16);
        words.set(7, BASE + 0x70L);
        Stm32InterruptPlan.Entry entry = entry("MAPPED_SINGLE", List.of(interrupt("WWDG_IRQn", 0)));
        Stm32VectorPlan plan = Stm32VectorPlanner.plan(entry, words, BASE, BASE, LENGTH);
        Stm32VectorPlan.Slot reserved = slot(plan, 7);
        assertEquals(Stm32VectorPlan.Kind.RESERVED, reserved.kind());
        assertNull(reserved.name());
        assertNull(reserved.label());
        assertEquals(BASE + 0x70L, reserved.rawWord());
    }

    @Test
    void recordsUnresolvedHandlerAddressesWithoutInventingFunctions() {
        List<Long> words = words(16);
        words.set(1, 0L);
        words.set(2, BASE);
        words.set(3, 0x2000_0001L);
        Stm32InterruptPlan.Entry entry = entry("MAPPED_SINGLE", List.of(
            interrupt("NonMaskableInt_IRQn", -14),
            interrupt("HardFault_IRQn", -13),
            interrupt("UsageFault_IRQn", -10)));
        Stm32VectorPlan plan = Stm32VectorPlanner.plan(entry, words, BASE, BASE, LENGTH);
        assertEquals(Stm32VectorPlan.HandlerStatus.ZERO, slot(plan, 1).handlerStatus());
        assertEquals(Stm32VectorPlan.HandlerStatus.NOT_THUMB, slot(plan, 2).handlerStatus());
        assertEquals(Stm32VectorPlan.HandlerStatus.OUT_OF_IMAGE, slot(plan, 3).handlerStatus());
        assertNull(slot(plan, 2).handlerAddress());

        Stm32InterruptPlan.Entry unmapped = entry("MAPPED_SINGLE",
            List.of(interrupt("EXTI0_IRQn", 6)));
        Stm32VectorPlan truncated = Stm32VectorPlanner.plan(unmapped, words(16), BASE, BASE, LENGTH);
        assertEquals(Stm32VectorPlan.HandlerStatus.SLOT_UNMAPPED, slot(truncated, 22).handlerStatus());
    }

    @Test
    void inapplicableInterruptListReturnsExplicitPlan() {
        Stm32InterruptPlan.Entry ambiguous = new Stm32InterruptPlan.Entry(
            "STM32N657X0H3Q", "CONDITIONAL_REVIEW", "stm32n657xx.h", List.of());
        Stm32VectorPlan plan = Stm32VectorPlanner.plan(ambiguous, words(16), BASE, BASE, LENGTH);
        assertFalse(plan.applicable());
        assertEquals("INTERRUPT_LIST_NOT_APPLICABLE", plan.reason());
        assertTrue(plan.slots().isEmpty());
    }

    @Test
    void unconfirmedOrUnknownBaseReturnsExplicitPlan() {
        Stm32VectorPlan plan = Stm32VectorPlanner.unconfirmed(PART, "VECTOR_TABLE_UNCONFIRMED");
        assertFalse(plan.applicable());
        assertEquals("VECTOR_TABLE_UNCONFIRMED", plan.reason());
        assertTrue(plan.tableAddress().isEmpty());
        assertThrows(IllegalArgumentException.class,
            () -> Stm32VectorPlanner.unconfirmed(" ", "reason"));
        assertThrows(NullPointerException.class,
            () -> Stm32VectorPlanner.unconfirmed(null, "reason"));
    }

    @Test
    void rejectsAmbiguousPinnedEntriesAndMalformedTables() {
        List<Long> words = words(16);
        Stm32InterruptPlan.Entry duplicateNumber = entry("MAPPED_SINGLE", List.of(
            interrupt("A_IRQn", 0), interrupt("B_IRQn", 0)));
        assertThrows(IllegalArgumentException.class,
            () -> Stm32VectorPlanner.plan(duplicateNumber, words, BASE, BASE, LENGTH));
        Stm32InterruptPlan.Entry duplicateName = entry("MAPPED_SINGLE", List.of(
            interrupt("A_IRQn", 0), interrupt("A_IRQn", 1)));
        assertThrows(IllegalArgumentException.class,
            () -> Stm32VectorPlanner.plan(duplicateName, words, BASE, BASE, LENGTH));
        Stm32InterruptPlan.Entry outOfRange = entry("MAPPED_SINGLE",
            List.of(interrupt("BAD_IRQn", -16)));
        assertThrows(IllegalArgumentException.class,
            () -> Stm32VectorPlanner.plan(outOfRange, words, BASE, BASE, LENGTH));
        Stm32InterruptPlan.Entry valid = entry("MAPPED_SINGLE",
            List.of(interrupt("WWDG_IRQn", 0)));
        assertThrows(IllegalArgumentException.class,
            () -> Stm32VectorPlanner.plan(valid, words, BASE + 2, BASE, LENGTH));
        assertThrows(IllegalArgumentException.class,
            () -> Stm32VectorPlanner.plan(valid, words(4), BASE, BASE, LENGTH));
        assertThrows(IllegalArgumentException.class,
            () -> Stm32VectorPlanner.plan(valid, words, BASE, BASE, 0));
        assertThrows(IllegalArgumentException.class,
            () -> Stm32VectorPlanner.plan(valid, words, BASE + LENGTH, BASE, LENGTH));
        assertThrows(NullPointerException.class,
            () -> Stm32VectorPlanner.plan(null, words, BASE, BASE, LENGTH));
        assertThrows(NullPointerException.class,
            () -> Stm32VectorPlanner.plan(valid, null, BASE, BASE, LENGTH));
    }

    @Test
    void plansEveryApplicableCuratedPartWithoutFabricatingExceptions() throws Exception {
        Stm32CuratedPartIds selection = Stm32CuratedPartIds.load(Path.of(
            "catalogs/stm32/2026-09-29/selection.json"), ParserLimits.defaults(),
            CancellationToken.none());
        Stm32InterruptPlan catalog = Stm32InterruptPlan.load(Path.of(
            "catalogs/stm32/2026-09-29/curated-catalog.json"), selection,
            ParserLimits.defaults(), CancellationToken.none());
        int applicable = 0;
        for (Stm32InterruptPlan.Entry part : catalog.entries()) {
            if (!part.applicable()) {
                assertFalse(Stm32VectorPlanner.plan(part, words(16), BASE, BASE, LENGTH)
                    .applicable());
                continue;
            }
            applicable++;
            int maxSlot = part.interrupts().stream().filter(irq -> irq.number() >= 0)
                .mapToInt(irq -> 16 + irq.number()).max().orElse(15);
            List<Long> words = words(maxSlot + 1);
            for (int slot = 1; slot < words.size(); slot++) {
                words.set(slot, BASE + 0x100L | 1L);
            }
            Stm32VectorPlan plan = Stm32VectorPlanner.plan(part, words, BASE, BASE, LENGTH);
            assertTrue(plan.applicable(), part.exactPart());
            assertEquals(Stm32VectorPlan.Kind.RESET, slot(plan, 1).kind());
            for (Stm32CoreException exception : Stm32CoreException.table()) {
                boolean pinned = part.interrupts().stream()
                    .anyMatch(irq -> irq.number() == exception.vectorNumber());
                Stm32VectorPlan.Slot planned = slot(plan, exception.slot());
                if (pinned) {
                    assertEquals(Stm32VectorPlan.Kind.CORE_EXCEPTION, planned.kind(),
                        part.exactPart() + " " + exception.handlerName());
                    assertEquals(exception.handlerName(), planned.name());
                }
                else {
                    assertEquals(Stm32VectorPlan.Kind.RESERVED, planned.kind(),
                        part.exactPart() + " " + exception.handlerName());
                    assertNull(planned.name());
                }
            }
        }
        assertEquals(51, applicable);
        Stm32VectorPlan c0 = null;
        for (Stm32InterruptPlan.Entry part : catalog.entries()) {
            if (part.exactPart().equals("STM32C031C6T3")) {
                c0 = Stm32VectorPlanner.plan(part, words(16), BASE, BASE, LENGTH);
            }
        }
        assertNotNull(c0);
        assertEquals(Stm32VectorPlan.Kind.RESERVED, slot(c0, 4).kind());
    }

    @Test
    void derivesImageRangeFromT039ValidatedMemoryPlan() throws Exception {
        Stm32CuratedPartIds selection = Stm32CuratedPartIds.load(Path.of(
            "catalogs/stm32/2026-09-29/selection.json"), ParserLimits.defaults(),
            CancellationToken.none());
        Stm32MemoryPlanner planner = Stm32MemoryPlanner.load(Path.of(
            "catalogs/stm32/2026-09-29/memory-plans.json"), selection,
            ParserLimits.defaults(), CancellationToken.none());
        Stm32VectorPlanner.ImageRange f103 = Stm32VectorPlanner.flashImageRange(
            planner.plan("STM32F103C8T6", Stm32MemoryPlanner.BootMode.UNKNOWN));
        assertEquals(BASE, f103.base());
        assertEquals(0x10000L, f103.length());
        assertThrows(IllegalArgumentException.class, () -> Stm32VectorPlanner.flashImageRange(
            planner.plan("STM32N657X0H3Q", Stm32MemoryPlanner.BootMode.UNKNOWN)));
        assertThrows(NullPointerException.class,
            () -> Stm32VectorPlanner.flashImageRange(null));
    }

    private static Stm32InterruptPlan.Entry entry(String status,
            List<Stm32InterruptPlan.Interrupt> interrupts) {
        return new Stm32InterruptPlan.Entry(PART, status, "cmsis-device-f1/Include/stm32f103xb.h",
            interrupts);
    }

    private static Stm32InterruptPlan.Interrupt interrupt(String name, int number) {
        return new Stm32InterruptPlan.Interrupt(name, number);
    }

    private static List<Long> words(int size) {
        return new ArrayList<>(Collections.nCopies(size, 0L));
    }

    private static Stm32VectorPlan.Slot slot(Stm32VectorPlan plan, int index) {
        return plan.slots().stream().filter(slot -> slot.slot() == index).findFirst()
            .orElseThrow(() -> new AssertionError("Missing slot " + index));
    }
}
