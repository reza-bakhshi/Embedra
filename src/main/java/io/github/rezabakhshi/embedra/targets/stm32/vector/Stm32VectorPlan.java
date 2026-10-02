package io.github.rezabakhshi.embedra.targets.stm32.vector;

import java.util.List;
import java.util.Objects;
import java.util.OptionalLong;

/**
 * Immutable, confirmed Cortex-M vector-slot plan for one exact STM32 part.
 *
 * <p>A plan is only {@link #applicable()} when the caller supplied a confirmed
 * vector table and the exact part has a single applicable interrupt list. Each
 * slot retains the raw confirmed word, the resolved Thumb handler address when
 * the word is an in-image handler, and the qualified label derived from the exact
 * part's pinned interrupt name or the explicit core-exception table. Reserved or
 * unnamed words stay {@code RESERVED}/unknown and are never fabricated.</p>
 */
public record Stm32VectorPlan(
        String exactPart,
        boolean applicable,
        String reason,
        OptionalLong tableAddress,
        long imageBase,
        long imageLength,
        List<Slot> slots,
        List<Diagnostic> diagnostics) {

    public Stm32VectorPlan {
        Objects.requireNonNull(exactPart, "exactPart");
        Objects.requireNonNull(reason, "reason");
        Objects.requireNonNull(tableAddress, "tableAddress");
        slots = List.copyOf(slots);
        diagnostics = List.copyOf(diagnostics);
    }

    /** Origin of a vector slot; core exceptions and device IRQs stay distinguishable. */
    public enum Kind {
        RESET, CORE_EXCEPTION, DEVICE_IRQ, RESERVED, STACK_POINTER
    }

    /** Resolution of a slot's raw word into an in-image Thumb handler address. */
    public enum HandlerStatus {
        RESOLVED, ZERO, NOT_THUMB, OUT_OF_IMAGE, SLOT_UNMAPPED, NOT_A_HANDLER
    }

    /**
     * One vector slot.
     *
     * @param slot index from the start of the confirmed table
     * @param vectorNumber CMSIS IRQ number ({@code slot - 16})
     * @param kind reset, core exception, device IRQ, reserved, or stack pointer
     * @param name deterministic base name, or {@code null} when unnamed
     * @param label qualified label for the resolved handler, or {@code null}
     * @param rawWord unsigned confirmed 32-bit word
     * @param handlerAddress Thumb-cleared in-image handler, or {@code null}
     * @param handlerStatus why the word did or did not resolve
     */
    public record Slot(int slot, int vectorNumber, Kind kind, String name, String label,
            long rawWord, Long handlerAddress, HandlerStatus handlerStatus) {
        public Slot {
            Objects.requireNonNull(kind, "kind");
            Objects.requireNonNull(handlerStatus, "handlerStatus");
            if (slot < 0 || vectorNumber != slot - 16
                    || rawWord < 0 || rawWord > 0xffff_ffffL) {
                throw new IllegalArgumentException("Vector slot is invalid");
            }
            if ((kind == Kind.RESET || kind == Kind.CORE_EXCEPTION || kind == Kind.DEVICE_IRQ)
                    && (name == null || label == null)) {
                throw new IllegalArgumentException("Named handler slots require a name and label");
            }
        }

        /** A named slot whose raw word resolves to an in-image Thumb handler. */
        public boolean resolvedHandler() {
            return name != null && handlerStatus == HandlerStatus.RESOLVED;
        }
    }

    /** Stable diagnostic for a plan-level condition. */
    public record Diagnostic(String code, String detail) {
        public Diagnostic {
            Objects.requireNonNull(code, "code");
            Objects.requireNonNull(detail, "detail");
        }
    }

    /** Explicit non-applicable result; no slot may be applied. */
    public static Stm32VectorPlan unconfirmed(String exactPart, String reason) {
        return new Stm32VectorPlan(exactPart, false, reason, OptionalLong.empty(), 0, 0,
            List.of(), List.of(new Diagnostic(reason, reason)));
    }

    /** Named slots carrying an explicit label, in slot order. */
    public List<Slot> namedSlots() {
        return slots.stream().filter(slot -> slot.name() != null).toList();
    }
}
