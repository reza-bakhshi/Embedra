package io.github.rezabakhshi.embedra.targets.rp;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Authoritative vector table model for the RP2040 ARM Cortex-M0+ microcontroller.
 * <p>
 * Standard table located at flash offset {@code 0x10000100} (192 bytes, 48 entries):
 * 16 ARM core exception vectors and 32 external user interrupts.
 */
public final class Rp2040VectorTable {

    public static final long DEFAULT_FLASH_VECTOR_TABLE_OFFSET = 0x10000100L;

    public static final int CORE_VECTOR_COUNT = 16;

    public static final int USER_IRQ_COUNT = 32;

    public static final int TOTAL_VECTOR_COUNT = CORE_VECTOR_COUNT + USER_IRQ_COUNT;

    public static final int TABLE_SIZE_BYTES = TOTAL_VECTOR_COUNT * 4;

    private static final Map<Integer, String> CORE_VECTORS;

    private static final Map<Integer, String> USER_IRQS;

    private static final Map<Integer, String> ALL_VECTORS;


    static {
        Map<Integer, String> core = new LinkedHashMap<>();
        core.put(0, "__initial_sp");
        core.put(1, "Reset_Handler");
        core.put(2, "NMI_Handler");
        core.put(3, "HardFault_Handler");
        core.put(11, "SVC_Handler");
        core.put(14, "PendSV_Handler");
        core.put(15, "SysTick_Handler");
        CORE_VECTORS = Collections.unmodifiableMap(core);

        Map<Integer, String> irqs = new LinkedHashMap<>();
        irqs.put(0, "TIMER_IRQ_0");
        irqs.put(1, "TIMER_IRQ_1");
        irqs.put(2, "TIMER_IRQ_2");
        irqs.put(3, "TIMER_IRQ_3");
        irqs.put(4, "PWM_IRQ_WRAP");
        irqs.put(5, "USBCTRL_IRQ");
        irqs.put(6, "XIP_IRQ");
        irqs.put(7, "PIO0_IRQ_0");
        irqs.put(8, "PIO0_IRQ_1");
        irqs.put(9, "PIO1_IRQ_0");
        irqs.put(10, "PIO1_IRQ_1");
        irqs.put(11, "DMA_IRQ_0");
        irqs.put(12, "DMA_IRQ_1");
        irqs.put(13, "IO_IRQ_BANK0");
        irqs.put(14, "IO_IRQ_QSPI");
        irqs.put(15, "SIO_IRQ_PROC0");
        irqs.put(16, "SIO_IRQ_PROC1");
        irqs.put(17, "CLOCKS_IRQ");
        irqs.put(18, "SPI0_IRQ");
        irqs.put(19, "SPI1_IRQ");
        irqs.put(20, "UART0_IRQ");
        irqs.put(21, "UART1_IRQ");
        irqs.put(22, "ADC_IRQ_FIFO");
        irqs.put(23, "I2C0_IRQ");
        irqs.put(24, "I2C1_IRQ");
        irqs.put(25, "RTC_IRQ");
        USER_IRQS = Collections.unmodifiableMap(irqs);

        Map<Integer, String> all = new LinkedHashMap<>();
        all.putAll(core);
        irqs.forEach((irqNum, name) -> all.put(CORE_VECTOR_COUNT + irqNum, name));
        ALL_VECTORS = Collections.unmodifiableMap(all);
    }

    private Rp2040VectorTable() {
    }

    public static Map<Integer, String> coreVectors() {
        return CORE_VECTORS;
    }

    public static Map<Integer, String> userIrqs() {
        return USER_IRQS;
    }

    public static Map<Integer, String> allVectors() {
        return ALL_VECTORS;
    }

    public static Optional<String> vectorName(int vectorIndex) {
        return Optional.ofNullable(ALL_VECTORS.get(vectorIndex));
    }

    public static Optional<String> irqName(int irqNumber) {
        return Optional.ofNullable(USER_IRQS.get(irqNumber));
    }
}
