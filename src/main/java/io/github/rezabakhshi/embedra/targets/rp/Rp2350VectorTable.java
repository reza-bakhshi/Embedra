package io.github.rezabakhshi.embedra.targets.rp;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Vector table models for the RP2350 family covering Cortex-M33 ARM and Hazard3 RISC-V.
 */
public final class Rp2350VectorTable {

    public static final int ARM_CORE_VECTOR_COUNT = 16;

    public static final int ARM_USER_IRQ_COUNT = 52;

    public static final int ARM_TOTAL_VECTOR_COUNT = ARM_CORE_VECTOR_COUNT + ARM_USER_IRQ_COUNT;

    private static final Map<Integer, String> ARM_CORE_VECTORS;

    private static final Map<Integer, String> ARM_USER_IRQS;

    private static final Map<Integer, String> ARM_ALL_VECTORS;

    private static final Map<Integer, String> RISCV_TRAP_VECTORS;


    static {
        Map<Integer, String> core = new LinkedHashMap<>();
        core.put(0, "__initial_sp");
        core.put(1, "Reset_Handler");
        core.put(2, "NMI_Handler");
        core.put(3, "HardFault_Handler");
        core.put(4, "MemManage_Handler");
        core.put(5, "BusFault_Handler");
        core.put(6, "UsageFault_Handler");
        core.put(7, "SecureFault_Handler");
        core.put(11, "SVC_Handler");
        core.put(12, "DebugMon_Handler");
        core.put(14, "PendSV_Handler");
        core.put(15, "SysTick_Handler");
        ARM_CORE_VECTORS = Collections.unmodifiableMap(core);

        Map<Integer, String> irqs = new LinkedHashMap<>();
        irqs.put(0, "TIMER0_IRQ_0");
        irqs.put(1, "TIMER0_IRQ_1");
        irqs.put(2, "TIMER0_IRQ_2");
        irqs.put(3, "TIMER0_IRQ_3");
        irqs.put(4, "TIMER1_IRQ_0");
        irqs.put(5, "TIMER1_IRQ_1");
        irqs.put(6, "TIMER1_IRQ_2");
        irqs.put(7, "TIMER1_IRQ_3");
        irqs.put(8, "PWM_IRQ_WRAP_0");
        irqs.put(9, "PWM_IRQ_WRAP_1");
        irqs.put(10, "DMA_IRQ_0");
        irqs.put(11, "DMA_IRQ_1");
        irqs.put(12, "DMA_IRQ_2");
        irqs.put(13, "DMA_IRQ_3");
        irqs.put(14, "USBCTRL_IRQ");
        irqs.put(15, "PIO0_IRQ_0");
        irqs.put(16, "PIO0_IRQ_1");
        irqs.put(17, "PIO1_IRQ_0");
        irqs.put(18, "PIO1_IRQ_1");
        irqs.put(19, "PIO2_IRQ_0");
        irqs.put(20, "PIO2_IRQ_1");
        irqs.put(21, "IO_IRQ_BANK0");
        irqs.put(22, "IO_IRQ_BANK0_NS");
        irqs.put(23, "IO_IRQ_QSPI");
        irqs.put(24, "IO_IRQ_QSPI_NS");
        irqs.put(25, "SIO_IRQ_FIFO");
        irqs.put(26, "SIO_IRQ_BELL");
        irqs.put(27, "SIO_IRQ_FIFO_NS");
        irqs.put(28, "SIO_IRQ_BELL_NS");
        irqs.put(29, "CLOCKS_IRQ");
        irqs.put(30, "SPI0_IRQ");
        irqs.put(31, "SPI1_IRQ");
        irqs.put(32, "UART0_IRQ");
        irqs.put(33, "UART1_IRQ");
        irqs.put(34, "UART2_IRQ");
        irqs.put(35, "I2C0_IRQ");
        irqs.put(36, "I2C1_IRQ");
        irqs.put(37, "ADC_IRQ_FIFO");
        irqs.put(38, "TRNG_IRQ");
        irqs.put(39, "SHA256_IRQ");
        ARM_USER_IRQS = Collections.unmodifiableMap(irqs);

        Map<Integer, String> allArm = new LinkedHashMap<>(core);
        irqs.forEach((k, v) -> allArm.put(ARM_CORE_VECTOR_COUNT + k, v));
        ARM_ALL_VECTORS = Collections.unmodifiableMap(allArm);

        Map<Integer, String> rv = new LinkedHashMap<>();
        rv.put(0, "reset_vector");
        rv.put(1, "trap_entry");
        rv.put(3, "machine_software_irq");
        rv.put(7, "machine_timer_irq");
        rv.put(11, "machine_external_irq");
        RISCV_TRAP_VECTORS = Collections.unmodifiableMap(rv);
    }

    private Rp2350VectorTable() {
    }

    public static Map<Integer, String> armCoreVectors() {
        return ARM_CORE_VECTORS;
    }

    public static Map<Integer, String> armUserIrqs() {
        return ARM_USER_IRQS;
    }

    public static Map<Integer, String> armAllVectors() {
        return ARM_ALL_VECTORS;
    }

    public static Map<Integer, String> riscvTrapVectors() {
        return RISCV_TRAP_VECTORS;
    }

    public static Optional<String> armVectorName(int vectorIndex) {
        return Optional.ofNullable(ARM_ALL_VECTORS.get(vectorIndex));
    }

    public static Optional<String> armIrqName(int irqNumber) {
        return Optional.ofNullable(ARM_USER_IRQS.get(irqNumber));
    }

    public static Optional<String> riscvVectorName(int cause) {
        return Optional.ofNullable(RISCV_TRAP_VECTORS.get(cause));
    }
}
