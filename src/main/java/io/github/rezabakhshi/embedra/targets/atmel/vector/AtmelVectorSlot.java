package io.github.rezabakhshi.embedra.targets.atmel.vector;

import io.github.rezabakhshi.embedra.targets.atmel.catalog.AtmelPartRecord;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Metadata definition for an interrupt vector slot in an Atmel / Microchip device.
 */
public record AtmelVectorSlot(
        int index,
        String name,
        String description) {

    public AtmelVectorSlot {
        Objects.requireNonNull(name, "name must not be null");
        Objects.requireNonNull(description, "description must not be null");
        if (index < 0) {
            throw new IllegalArgumentException("Vector index must be non-negative: " + index);
        }
    }

    public static List<AtmelVectorSlot> slotsFor(AtmelPartRecord part) {
        Objects.requireNonNull(part, "part must not be null");
        int count = part.vectorCount();
        List<AtmelVectorSlot> slots = new ArrayList<>(count);

        if (part.isSam()) {
            return generateSamSlots(count);
        } else if ("ATmega328P".equalsIgnoreCase(part.exactPart())) {
            return generateAtmega328pSlots();
        } else if ("ATtiny85".equalsIgnoreCase(part.exactPart())) {
            return generateAttiny85Slots();
        } else {
            return generateGenericAvrSlots(part);
        }
    }

    private static List<AtmelVectorSlot> generateSamSlots(int count) {
        List<AtmelVectorSlot> slots = new ArrayList<>(count);
        String[] cortexExceptions = {
            "Initial_SP", "Reset", "NMI", "HardFault", "MemManage",
            "BusFault", "UsageFault", "Reserved7", "Reserved8", "Reserved9",
            "Reserved10", "SVCall", "DebugMon", "Reserved13", "PendSV", "SysTick"
        };
        for (int i = 0; i < count; i++) {
            if (i < cortexExceptions.length) {
                slots.add(new AtmelVectorSlot(i, cortexExceptions[i], "Cortex-M System Exception " + i));
            } else {
                int irq = i - 16;
                slots.add(new AtmelVectorSlot(i, "IRQ" + irq, "Peripheral Interrupt " + irq));
            }
        }
        return slots;
    }

    private static List<AtmelVectorSlot> generateAtmega328pSlots() {
        String[] names = {
            "RESET", "INT0", "INT1", "PCINT0", "PCINT1", "PCINT2", "WDT",
            "TIMER2_COMPA", "TIMER2_COMPB", "TIMER2_OVF", "TIMER1_CAPT",
            "TIMER1_COMPA", "TIMER1_COMPB", "TIMER1_OVF", "TIMER0_COMPA",
            "TIMER0_COMPB", "TIMER0_OVF", "SPI_STC", "USART_RX", "USART_UDRE",
            "USART_TX", "ADC", "EE_READY", "ANALOG_COMP", "TWI", "SPM_READY"
        };
        List<AtmelVectorSlot> slots = new ArrayList<>(names.length);
        for (int i = 0; i < names.length; i++) {
            slots.add(new AtmelVectorSlot(i, names[i] + "_vect", "ATmega328P Vector " + (i + 1) + ": " + names[i]));
        }
        return slots;
    }

    private static List<AtmelVectorSlot> generateAttiny85Slots() {
        String[] names = {
            "RESET", "INT0", "PCINT0", "TIMER1_COMPA", "TIMER1_OVF",
            "TIMER0_OVF", "EE_RDY", "ANA_COMP", "ADC", "TIMER1_COMPB",
            "TIMER0_COMPA", "TIMER0_COMPB", "WDT", "USI_START", "USI_OVF"
        };
        List<AtmelVectorSlot> slots = new ArrayList<>(names.length);
        for (int i = 0; i < names.length; i++) {
            slots.add(new AtmelVectorSlot(i, names[i] + "_vect", "ATtiny85 Vector " + (i + 1) + ": " + names[i]));
        }
        return slots;
    }

    private static List<AtmelVectorSlot> generateGenericAvrSlots(AtmelPartRecord part) {
        int count = part.vectorCount();
        List<AtmelVectorSlot> slots = new ArrayList<>(count);
        slots.add(new AtmelVectorSlot(0, "RESET_vect", "Power-on, external reset, watchdog, or brown-out"));
        for (int i = 1; i < count; i++) {
            slots.add(new AtmelVectorSlot(i, "__vector_" + i, part.exactPart() + " Interrupt Vector " + (i + 1)));
        }
        return slots;
    }
}
