package io.github.rezabakhshi.embedra.targets.stm32.vector;

import io.github.rezabakhshi.embedra.targets.stm32.catalog.Stm32InterruptPlan;
import io.github.rezabakhshi.embedra.targets.stm32.memory.Stm32MemoryPlanner;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.TreeMap;

/**
 * Builds a confirmed Cortex-M vector-slot plan from a T037 confirmation, the
 * T040 exact-part interrupt list, and an explicit image range.
 *
 * <p>The planner is pure: it never reads Ghidra memory. The caller supplies the
 * confirmed vector words and the image base/length, so handler addresses resolve
 * only from a confirmed table. Inapplicable or conditional interrupt lists return
 * an explicit non-applicable plan; malformed tables, ambiguous pinned entries,
 * and unknown numbers fail closed instead of guessing a name or address.</p>
 */
public final class Stm32VectorPlanner {
    /** Ignored by the planner; a standard 32-bit Cortex-M vector word is always four bytes. */
    public static final int VECTOR_BYTES = 4;

    /** Reset, the nine architectural exceptions, reserved slots, and the stack pointer. */
    public static final int CORE_SLOTS = 16;

    private static final long ADDRESS_SPACE_END = 0x1_0000_0000L;

    private Stm32VectorPlanner() {
    }

    /** Explicit non-applicable plan for an unconfirmed table or an unknown base. */
    public static Stm32VectorPlan unconfirmed(String exactPart, String reason) {
        Objects.requireNonNull(exactPart, "exactPart");
        Objects.requireNonNull(reason, "reason");
        if (exactPart.isBlank() || reason.isBlank()) {
            throw new IllegalArgumentException("Unconfirmed plan requires a part and reason");
        }
        return Stm32VectorPlan.unconfirmed(exactPart, reason);
    }

    /** Confirmed image extent used to validate handler containment. */
    public record ImageRange(long base, long length) {
        public ImageRange {
            if (base < 0 || length <= 0 || base >= ADDRESS_SPACE_END
                    || length > ADDRESS_SPACE_END - base) {
                throw new IllegalArgumentException("Image range is outside the 32-bit space");
            }
        }
    }

    /**
     * Derives the confirmed image extent from the T039 exact-part FLASH region.
     *
     * <p>This is the explicit T039 linkage: the caller composes the validated
     * memory plan instead of hard-coding a base. A part with no validated flash
     * region (for example a ROMless device) fails closed.</p>
     */
    public static ImageRange flashImageRange(Stm32MemoryPlanner.Plan plan) {
        Objects.requireNonNull(plan, "plan");
        for (Stm32MemoryPlanner.Region region : plan.regions()) {
            if ("FLASH".equals(region.kind())) {
                return new ImageRange(region.range().start(), region.range().length());
            }
        }
        throw new IllegalArgumentException(
            "Memory plan has no validated flash region: " + plan.exactPart());
    }

    /**
     * Builds a plan for one exact part from its pinned interrupt list and the
     * confirmed vector words.
     *
     * @param entry exact-part interrupt entry from {@code Stm32InterruptPlan}
     * @param words confirmed 32-bit vector words starting at slot zero
     * @param tableAddress confirmed table address; must be four-byte aligned
     * @param imageBase confirmed image base
     * @param imageLength confirmed image length in bytes
     * @return an applicable or explicit non-applicable plan
     * @throws IllegalArgumentException when the confirmed table is malformed
     */
    public static Stm32VectorPlan plan(Stm32InterruptPlan.Entry entry, List<Long> words,
            long tableAddress, long imageBase, long imageLength) {
        Objects.requireNonNull(entry, "entry");
        Objects.requireNonNull(words, "words");
        if (!entry.applicable()) {
            return new Stm32VectorPlan(entry.exactPart(), false, "INTERRUPT_LIST_NOT_APPLICABLE",
                OptionalLong.empty(), imageBase, imageLength, List.of(),
                List.of(new Stm32VectorPlan.Diagnostic("INTERRUPT_LIST_NOT_APPLICABLE",
                    "Interrupt mapping is not a single applicable header: " + entry.status())));
        }
        requireRange(tableAddress, imageBase, imageLength);
        if (words.size() < CORE_SLOTS) {
            throw new IllegalArgumentException("Confirmed vector table is truncated");
        }
        List<Long> confirmed = List.copyOf(words);
        Map<Integer, String> pinned = index(entry);
        List<Stm32VectorPlan.Diagnostic> diagnostics = new ArrayList<>();
        List<Stm32VectorPlan.Slot> slots = new ArrayList<>(coreSlots(entry.exactPart(),
            confirmed, pinned, diagnostics, imageBase, imageLength));
        slots.addAll(deviceSlots(entry.exactPart(), confirmed, pinned, imageBase, imageLength));
        return new Stm32VectorPlan(entry.exactPart(), true, "CONFIRMED", OptionalLong.of(tableAddress),
            imageBase, imageLength, slots, diagnostics);
    }

    private static List<Stm32VectorPlan.Slot> coreSlots(String exactPart, List<Long> confirmed,
            Map<Integer, String> pinned, List<Stm32VectorPlan.Diagnostic> diagnostics,
            long imageBase, long imageLength) {
        List<Stm32VectorPlan.Slot> slots = new ArrayList<>(CORE_SLOTS);
        for (int slot = 0; slot < CORE_SLOTS; slot++) {
            if (slot == 0) {
                slots.add(build(slot, Stm32VectorPlan.Kind.STACK_POINTER, null, null,
                    confirmed.get(0), imageBase, imageLength, null));
                continue;
            }
            if (slot == 1) {
                slots.add(build(slot, Stm32VectorPlan.Kind.RESET, Stm32CoreException.RESET_NAME,
                    label(exactPart, Stm32CoreException.RESET_NAME), confirmed.get(slot),
                    imageBase, imageLength, null));
                continue;
            }
            int number = slot - 16;
            String pinnedName = pinned.get(number);
            Optional<Stm32CoreException> standard = Stm32CoreException.forSlot(slot);
            if (pinnedName == null) {
                if (standard.isPresent()) {
                    diagnostics.add(new Stm32VectorPlan.Diagnostic("CORE_EXCEPTION_ABSENT",
                        "Pinned list omits " + standard.get().handlerName()));
                }
                slots.add(build(slot, Stm32VectorPlan.Kind.RESERVED, null, null,
                    confirmed.get(slot), imageBase, imageLength, null));
            }
            else if (standard.isPresent()) {
                Stm32CoreException exception = standard.get();
                slots.add(build(slot, Stm32VectorPlan.Kind.CORE_EXCEPTION, exception.handlerName(),
                    label(exactPart, exception.handlerName()), confirmed.get(slot),
                    imageBase, imageLength, null));
            }
            else {
                diagnostics.add(new Stm32VectorPlan.Diagnostic("UNLISTED_CORE_EXCEPTION",
                    "Pinned core exception is not in the explicit table: " + pinnedName));
                slots.add(build(slot, Stm32VectorPlan.Kind.CORE_EXCEPTION, pinnedName,
                    label(exactPart, pinnedName), confirmed.get(slot),
                    imageBase, imageLength, null));
            }
        }
        return slots;
    }

    private static List<Stm32VectorPlan.Slot> deviceSlots(String exactPart, List<Long> confirmed,
            Map<Integer, String> pinned, long imageBase, long imageLength) {
        List<Stm32VectorPlan.Slot> slots = new ArrayList<>();
        for (Map.Entry<Integer, String> entry : pinned.entrySet()) {
            int number = entry.getKey();
            if (number < 0) {
                continue;
            }
            int slot = 16 + number;
            boolean covered = slot < confirmed.size();
            slots.add(build(slot, Stm32VectorPlan.Kind.DEVICE_IRQ, entry.getValue(),
                label(exactPart, entry.getValue()), covered ? confirmed.get(slot) : 0,
                imageBase, imageLength,
                covered ? null : Stm32VectorPlan.HandlerStatus.SLOT_UNMAPPED));
        }
        return slots;
    }

    private static Stm32VectorPlan.Slot build(int slot, Stm32VectorPlan.Kind kind, String name,
            String label, long rawWord, long imageBase, long imageLength,
            Stm32VectorPlan.HandlerStatus forced) {
        int number = slot - 16;
        if (kind == Stm32VectorPlan.Kind.STACK_POINTER) {
            return new Stm32VectorPlan.Slot(slot, number, kind, null, null, rawWord, null,
                Stm32VectorPlan.HandlerStatus.NOT_A_HANDLER);
        }
        if (forced == Stm32VectorPlan.HandlerStatus.SLOT_UNMAPPED) {
            return new Stm32VectorPlan.Slot(slot, number, kind, name, label, 0, null, forced);
        }
        if (rawWord == 0) {
            return new Stm32VectorPlan.Slot(slot, number, kind, name, label, rawWord, null,
                Stm32VectorPlan.HandlerStatus.ZERO);
        }
        if ((rawWord & 1L) == 0) {
            return new Stm32VectorPlan.Slot(slot, number, kind, name, label, rawWord, null,
                Stm32VectorPlan.HandlerStatus.NOT_THUMB);
        }
        long handler = rawWord & ~1L;
        if (handler < imageBase || handler >= imageBase + imageLength) {
            return new Stm32VectorPlan.Slot(slot, number, kind, name, label, rawWord, null,
                Stm32VectorPlan.HandlerStatus.OUT_OF_IMAGE);
        }
        return new Stm32VectorPlan.Slot(slot, number, kind, name, label, rawWord, handler,
            Stm32VectorPlan.HandlerStatus.RESOLVED);
    }

    private static Map<Integer, String> index(Stm32InterruptPlan.Entry entry) {
        Map<Integer, String> byNumber = new TreeMap<>();
        Map<String, Integer> byName = new TreeMap<>();
        for (Stm32InterruptPlan.Interrupt interrupt : entry.interrupts()) {
            int number = interrupt.number();
            if (number < Stm32CoreException.RESET_VECTOR_NUMBER || number > 65535) {
                throw new IllegalArgumentException(
                    "Pinned interrupt number is outside the Cortex-M range: " + number);
            }
            if (byNumber.putIfAbsent(number, interrupt.name()) != null) {
                throw new IllegalArgumentException("Duplicate pinned interrupt number: " + number);
            }
            if (byName.putIfAbsent(interrupt.name(), number) != null) {
                throw new IllegalArgumentException(
                    "Duplicate pinned interrupt name: " + interrupt.name());
            }
        }
        return byNumber;
    }

    private static void requireRange(long tableAddress, long imageBase, long imageLength) {
        if (tableAddress < 0 || tableAddress >= ADDRESS_SPACE_END || (tableAddress & 3) != 0) {
            throw new IllegalArgumentException("Confirmed vector table address is invalid");
        }
        if (imageBase < 0 || imageLength <= 0 || imageBase >= ADDRESS_SPACE_END
                || imageLength > ADDRESS_SPACE_END - imageBase
                || tableAddress < imageBase || tableAddress >= imageBase + imageLength) {
            throw new IllegalArgumentException("Confirmed image range is invalid");
        }
    }

    private static String label(String exactPart, String name) {
        return (exactPart + "_" + name).replaceAll("[^A-Za-z0-9_$]", "_");
    }
}
