package io.github.rezabakhshi.embedra.targets.stm32.vector;

import java.util.List;
import java.util.Optional;

/**
 * Explicit Cortex-M architectural core exceptions.
 *
 * <p>The table is intentionally separate from device IRQs. It fixes the canonical
 * handler base name and the negative CMSIS IRQ number for each standard exception.
 * Applicability to one exact part is decided from that part's pinned interrupt
 * list, so a reduced Armv6-M core never gains an exception it does not implement.
 * Reset is architectural but is not expressed as an {@code IRQn} in CMSIS, so it is
 * carried as an explicit constant rather than a fabricated enum value.</p>
 */
public enum Stm32CoreException {
    NON_MASKABLE_INT("NonMaskableInt", -14),
    HARD_FAULT("HardFault", -13),
    MEM_MANAGE("MemManage", -12),
    BUS_FAULT("BusFault", -11),
    USAGE_FAULT("UsageFault", -10),
    SV_CALL("SVCall", -5),
    DEBUG_MONITOR("DebugMonitor", -4),
    PEND_SV("PendSV", -2),
    SYS_TICK("SysTick", -1);

    /** CMSIS defines {@code Reset_IRQn} as {@code -15}; it always owns vector slot 1. */
    public static final int RESET_VECTOR_NUMBER = -15;

    /** Architectural reset handler base name. */
    public static final String RESET_NAME = "Reset";

    private final String handlerName;

    private final int vectorNumber;

    Stm32CoreException(String handlerName, int vectorNumber) {
        this.handlerName = handlerName;
        this.vectorNumber = vectorNumber;
    }

    /** Deterministic base name for a qualified handler label. */
    public String handlerName() {
        return handlerName;
    }

    /** Negative CMSIS exception number shared with the pinned interrupt list. */
    public int vectorNumber() {
        return vectorNumber;
    }

    /** Cortex-M vector slot; exception numbers map linearly as {@code 16 + number}. */
    public int slot() {
        return 16 + vectorNumber;
    }

    /** Looks up the standard exception that owns a CMSIS vector number. */
    public static Optional<Stm32CoreException> forVectorNumber(int number) {
        for (Stm32CoreException exception : values()) {
            if (exception.vectorNumber == number) {
                return Optional.of(exception);
            }
        }
        return Optional.empty();
    }

    /** Looks up the standard exception that owns a Cortex-M vector slot. */
    public static Optional<Stm32CoreException> forSlot(int slot) {
        return forVectorNumber(slot - 16);
    }

    /** Immutable enumeration order for deterministic plans and tests. */
    public static List<Stm32CoreException> table() {
        return List.of(values());
    }
}
