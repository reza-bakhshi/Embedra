package io.github.rezabakhshi.embedra.svd;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Optional;
import java.util.OptionalLong;
import org.junit.jupiter.api.Test;

class Stm32SvdModelTest {
    private static Stm32SvdField field(String name, int offset, int width,
            EspSvdAccess access, List<Stm32SvdEnumeratedValue> values) {
        return new Stm32SvdField(name, "", offset, width, access, OptionalLong.empty(),
            Optional.empty(), values);
    }

    private static Stm32SvdRegister register(String name, long address, int sizeBits,
            List<Stm32SvdField> fields) {
        return new Stm32SvdRegister(name, "", address, sizeBits, EspSvdAccess.READ_WRITE,
            OptionalLong.empty(), OptionalLong.empty(), fields, Optional.empty(),
            Optional.empty());
    }

    @Test
    void exposesFieldsEnumerationsAndAlternateViews() {
        Stm32SvdField enable = field("EN", 0, 1, EspSvdAccess.READ_WRITE, List.of(
            new Stm32SvdEnumeratedValue("Off", 0, "", false),
            new Stm32SvdEnumeratedValue("On", 1, "on", true)));
        Stm32SvdRegister control = new Stm32SvdRegister("CTRL", "control", 0x40000000L,
            32, EspSvdAccess.READ_WRITE, OptionalLong.of(1), OptionalLong.empty(),
            List.of(enable), Optional.of("CTRL_ALT"), Optional.empty());
        assertTrue(control.hasFields());
        assertTrue(control.isAlternateView());
        assertTrue(enable.hasEnumeration());
        Stm32SvdPeripheral peripheral = new Stm32SvdPeripheral("BASE", "", "GRP",
            0x40000000L, 0x40000400L, List.of(control),
            List.of(new Stm32SvdInterrupt("BASE_IRQn", 7, "")));
        Stm32SvdDevice device = new Stm32SvdDevice("STM32SYN", "rev", List.of(peripheral));
        assertEquals(1, device.peripherals().size());
        assertEquals(1, device.interrupts().size());
        assertTrue(device.ambiguousInterruptNames().isEmpty());
        assertEquals(7, device.interrupts().get(0).number());
        assertThrows(IllegalArgumentException.class,
            () -> device.requirePeripheral("MISSING"));
        assertThrows(IllegalArgumentException.class,
            () -> peripheral.requireRegister("MISSING"));
    }

    @Test
    void flagsAmbiguousInterruptNamesAcrossPeripherals() {
        Stm32SvdPeripheral first = new Stm32SvdPeripheral("A", "", "", 0x40000000L,
            0x40000004L, List.of(),
            List.of(new Stm32SvdInterrupt("SHARED", 1, "")));
        Stm32SvdPeripheral second = new Stm32SvdPeripheral("B", "", "", 0x40001000L,
            0x40001004L, List.of(),
            List.of(new Stm32SvdInterrupt("SHARED", 2, "")));
        Stm32SvdDevice device = new Stm32SvdDevice("D", "rev", List.of(first, second));
        assertEquals(List.of("SHARED"), List.copyOf(device.ambiguousInterruptNames()));
    }

    @Test
    void rejectsInvalidModelShapes() {
        assertThrows(IllegalArgumentException.class, () -> field("F", 0, 0,
            EspSvdAccess.READ_WRITE, List.of()));
        assertThrows(IllegalArgumentException.class, () -> new Stm32SvdEnumeratedValue(
            "", 1, "", false));
        assertThrows(IllegalArgumentException.class, () -> new Stm32SvdInterrupt(
            "IRQ", -17, ""));
        Stm32SvdField tooWide = field("F", 30, 4, EspSvdAccess.READ_WRITE, List.of());
        assertThrows(IllegalArgumentException.class,
            () -> register("R", 0x40000000L, 32, List.of(tooWide)));
        assertThrows(IllegalArgumentException.class, () -> {
            Stm32SvdField badEnum = field("F", 0, 1, EspSvdAccess.READ_WRITE,
                List.of(new Stm32SvdEnumeratedValue("V", 4, "", false)));
            register("R", 0x40000000L, 32, List.of(badEnum));
        });
        Stm32SvdField overlapA = field("A", 0, 4, EspSvdAccess.READ_WRITE, List.of());
        Stm32SvdField overlapB = field("B", 3, 4, EspSvdAccess.READ_WRITE, List.of());
        assertThrows(IllegalArgumentException.class, () ->
            register("R", 0x40000000L, 32, List.of(overlapA, overlapB)));
        Stm32SvdField duplicateA = field("DUP", 0, 1, EspSvdAccess.READ_WRITE, List.of());
        Stm32SvdField duplicateB = field("DUP", 1, 1, EspSvdAccess.READ_WRITE, List.of());
        assertThrows(IllegalArgumentException.class, () ->
            register("R", 0x40000000L, 32, List.of(duplicateA, duplicateB)));
        assertThrows(IllegalArgumentException.class, () -> field("F", 0, 2,
            EspSvdAccess.READ_WRITE, List.of(
                new Stm32SvdEnumeratedValue("V", 0, "", false),
                new Stm32SvdEnumeratedValue("V", 1, "", false))));
        Stm32SvdRegister outside = register("R", 0x4000ffffL, 32, List.of());
        assertThrows(IllegalArgumentException.class, () -> new Stm32SvdPeripheral("P", "",
            "", 0x40000000L, 0x40000100L, List.of(outside), List.of()));
        assertThrows(IllegalArgumentException.class, () -> new Stm32SvdPeripheral("P", "",
            "", 0x40000000L, 0x40000000L, List.of(), List.of()));
        assertFalse(new Stm32SvdDevice("D", "rev", List.of(new Stm32SvdPeripheral("P", "",
            "", 0x40000000L, 0x40000004L, List.of(), List.of())))
            .ambiguousInterruptNames().contains("X"));
    }
}
