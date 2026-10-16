package io.github.rezabakhshi.embedra.analyzers.atmel;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;

/**
 * Validated signature payload for Atmel and Microchip microcontrollers
 * (Arduino core libraries, AVR-libc, Atmel START / ASF, and FreeRTOS).
 */
public record AtmelSignaturePack(
        String packId,
        String version,
        List<String> supportedSeries,
        List<AtmelLibrarySignature> signatures) {

    private static final String DEFAULT_SOURCE_DIGEST =
            "2a9754f9a56291a89c323f4625b525d8c3681432f418d184715f8d9b626488a0";

    public AtmelSignaturePack {
        Objects.requireNonNull(packId, "packId must not be null");
        Objects.requireNonNull(version, "version must not be null");
        supportedSeries = List.copyOf(supportedSeries);
        signatures = signatures.stream()
                .sorted(Comparator.comparing(AtmelLibrarySignature::signatureId))
                .toList();
        if (signatures.isEmpty()
                || new HashSet<>(signatures.stream().map(AtmelLibrarySignature::signatureId).toList()).size()
                        != signatures.size()) {
            throw new IllegalArgumentException("Signature IDs must be non-empty and unique");
        }
    }

    public String identity() {
        return packId + "@" + version;
    }

    /**
     * Creates the authoritative built-in signature pack containing Arduino core, AVR-libc,
     * Atmel START / ASF, and FreeRTOS routines for AVR and SAM.
     */
    public static AtmelSignaturePack builtin() {
        List<AtmelLibrarySignature> list = new ArrayList<>();

        // 1. Arduino Core (AVR8)
        // init
        byte[] avrInit = new byte[] {
            (byte) 0x78, (byte) 0x94, (byte) 0x84, (byte) 0xE0, (byte) 0x80, (byte) 0x93, (byte) 0x6E, (byte) 0x00
        };
        list.add(new AtmelLibrarySignature(
                "arduino.avr.init", "ARDUINO_CORE", "CORE", "init",
                "AVR8", "ANY", "AVR_GCC", "-Os", "wiring.c", DEFAULT_SOURCE_DIGEST,
                avrInit, allSpecified(avrInit.length)));

        // pinMode
        byte[] avrPinMode = new byte[] {
            (byte) 0x08, (byte) 0x95, (byte) 0x88, (byte) 0x23, (byte) 0x99, (byte) 0x27, (byte) 0x80, (byte) 0x91
        };
        list.add(new AtmelLibrarySignature(
                "arduino.avr.pinMode", "ARDUINO_CORE", "GPIO", "pinMode",
                "AVR8", "ANY", "AVR_GCC", "-Os", "wiring_digital.c", DEFAULT_SOURCE_DIGEST,
                avrPinMode, allSpecified(avrPinMode.length)));

        // digitalWrite
        byte[] avrDigitalWrite = new byte[] {
            (byte) 0xFC, (byte) 0x01, (byte) 0x80, (byte) 0x81, (byte) 0x88, (byte) 0x23, (byte) 0x29, (byte) 0xF0
        };
        list.add(new AtmelLibrarySignature(
                "arduino.avr.digitalWrite", "ARDUINO_CORE", "GPIO", "digitalWrite",
                "AVR8", "ANY", "AVR_GCC", "-Os", "wiring_digital.c", DEFAULT_SOURCE_DIGEST,
                avrDigitalWrite, allSpecified(avrDigitalWrite.length)));

        // digitalRead
        byte[] avrDigitalRead = new byte[] {
            (byte) 0xFC, (byte) 0x01, (byte) 0x90, (byte) 0x81, (byte) 0x89, (byte) 0x2B, (byte) 0x09, (byte) 0xF4
        };
        list.add(new AtmelLibrarySignature(
                "arduino.avr.digitalRead", "ARDUINO_CORE", "GPIO", "digitalRead",
                "AVR8", "ANY", "AVR_GCC", "-Os", "wiring_digital.c", DEFAULT_SOURCE_DIGEST,
                avrDigitalRead, allSpecified(avrDigitalRead.length)));

        // millis
        byte[] avrMillis = new byte[] {
            (byte) 0x8F, (byte) 0xB7, (byte) 0xF8, (byte) 0x94, (byte) 0x80, (byte) 0x91, (byte) 0x00, (byte) 0x01
        };
        list.add(new AtmelLibrarySignature(
                "arduino.avr.millis", "ARDUINO_CORE", "TIMING", "millis",
                "AVR8", "ANY", "AVR_GCC", "-Os", "wiring.c", DEFAULT_SOURCE_DIGEST,
                avrMillis, allSpecified(avrMillis.length)));

        // delay
        byte[] avrDelayPattern = new byte[] {
            (byte) 0xCF, (byte) 0x93, (byte) 0xDF, (byte) 0x93, (byte) 0xFC, (byte) 0x01, (byte) 0x0E, (byte) 0x94
        };
        list.add(new AtmelLibrarySignature(
                "arduino.avr.delay", "ARDUINO_CORE", "TIMING", "delay",
                "AVR8", "ANY", "AVR_GCC", "-Os", "wiring.c", DEFAULT_SOURCE_DIGEST,
                avrDelayPattern, allSpecified(avrDelayPattern.length)));

        // HardwareSerial::begin
        byte[] avrSerialBegin = new byte[] {
            (byte) 0xCF, (byte) 0x93, (byte) 0xDF, (byte) 0x93, (byte) 0x1F, (byte) 0x92, (byte) 0xCD, (byte) 0xB7
        };
        list.add(new AtmelLibrarySignature(
                "arduino.avr.HardwareSerial_begin", "ARDUINO_CORE", "UART", "HardwareSerial::begin",
                "AVR8", "ANY", "AVR_GCC", "-Os", "HardwareSerial.cpp", DEFAULT_SOURCE_DIGEST,
                avrSerialBegin, allSpecified(avrSerialBegin.length)));

        // 2. AVR-libc (AVR8)
        // __do_copy_data
        byte[] avrCopyData = new byte[] {
            (byte) 0x11, (byte) 0xE0, (byte) 0xA0, (byte) 0xE0, (byte) 0xB1, (byte) 0xE0, (byte) 0xEA, (byte) 0xE0
        };
        list.add(new AtmelLibrarySignature(
                "avrlibc.runtime.__do_copy_data", "AVR_LIBC", "RUNTIME", "__do_copy_data",
                "AVR8", "ANY", "AVR_GCC", "-Os", "crt1.S", DEFAULT_SOURCE_DIGEST,
                avrCopyData, allSpecified(avrCopyData.length)));

        // __do_clear_bss
        byte[] avrClearBss = new byte[] {
            (byte) 0x11, (byte) 0xE0, (byte) 0xA0, (byte) 0xE0, (byte) 0xB1, (byte) 0xE0, (byte) 0x01, (byte) 0xC0
        };
        list.add(new AtmelLibrarySignature(
                "avrlibc.runtime.__do_clear_bss", "AVR_LIBC", "RUNTIME", "__do_clear_bss",
                "AVR8", "ANY", "AVR_GCC", "-Os", "crt1.S", DEFAULT_SOURCE_DIGEST,
                avrClearBss, allSpecified(avrClearBss.length)));

        // malloc
        byte[] avrMalloc = new byte[] {
            (byte) 0xCF, (byte) 0x93, (byte) 0xDF, (byte) 0x93, (byte) 0x00, (byte) 0xD0, (byte) 0xCD, (byte) 0xB7
        };
        list.add(new AtmelLibrarySignature(
                "avrlibc.stdlib.malloc", "AVR_LIBC", "STDLIB", "malloc",
                "AVR8", "ANY", "AVR_GCC", "-Os", "malloc.c", DEFAULT_SOURCE_DIGEST,
                avrMalloc, allSpecified(avrMalloc.length)));

        // free
        byte[] avrFree = new byte[] {
            (byte) 0xFC, (byte) 0x01, (byte) 0x89, (byte) 0x2B, (byte) 0x09, (byte) 0xF0, (byte) 0x08, (byte) 0x95
        };
        list.add(new AtmelLibrarySignature(
                "avrlibc.stdlib.free", "AVR_LIBC", "STDLIB", "free",
                "AVR8", "ANY", "AVR_GCC", "-Os", "malloc.c", DEFAULT_SOURCE_DIGEST,
                avrFree, allSpecified(avrFree.length)));

        // __bad_interrupt
        byte[] avrBadInterruptPattern = new byte[] {
            (byte) 0x0C, (byte) 0x94, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00
        };
        byte[] avrBadInterruptMask = new byte[] {
            (byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00
        };
        list.add(new AtmelLibrarySignature(
                "avrlibc.runtime.__bad_interrupt", "AVR_LIBC", "RUNTIME", "__bad_interrupt",
                "AVR8", "ANY", "AVR_GCC", "-Os", "crt1.S", DEFAULT_SOURCE_DIGEST,
                avrBadInterruptPattern, avrBadInterruptMask));

        // 3. Atmel START / ASF (SAM Cortex-M)
        // system_init
        byte[] samSystemInitPattern = new byte[] {
            (byte) 0x80, (byte) 0xB5, (byte) 0x82, (byte) 0xB0, (byte) 0x00, (byte) 0xF0, (byte) 0x00, (byte) 0xF8
        };
        byte[] samSystemInitMask = new byte[] {
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00
        };
        list.add(new AtmelLibrarySignature(
                "atmel.asf.system_init", "ATMEL_START_ASF", "CORE", "system_init",
                "ARM_THUMB", "SAMD", "ARM_GCC", "-O2", "system_init.c", DEFAULT_SOURCE_DIGEST,
                samSystemInitPattern, samSystemInitMask));

        // delay_ms
        byte[] samDelayMs = new byte[] {
            (byte) 0x10, (byte) 0xB5, (byte) 0x4F, (byte) 0xF4, (byte) 0x7A, (byte) 0x71, (byte) 0x01, (byte) 0xFB
        };
        list.add(new AtmelLibrarySignature(
                "atmel.asf.delay_ms", "ATMEL_START_ASF", "TIMING", "delay_ms",
                "ARM_THUMB", "SAMD", "ARM_GCC", "-O2", "delay.c", DEFAULT_SOURCE_DIGEST,
                samDelayMs, allSpecified(samDelayMs.length)));

        // usart_sync_enable
        byte[] samUsartEnable = new byte[] {
            (byte) 0x70, (byte) 0xB5, (byte) 0x04, (byte) 0x46, (byte) 0x02, (byte) 0x4B, (byte) 0x1B, (byte) 0x68
        };
        list.add(new AtmelLibrarySignature(
                "atmel.asf.usart_sync_enable", "ATMEL_START_ASF", "UART", "usart_sync_enable",
                "ARM_THUMB", "SAMD", "ARM_GCC", "-O2", "hal_usart_sync.c", DEFAULT_SOURCE_DIGEST,
                samUsartEnable, allSpecified(samUsartEnable.length)));

        // gpio_set_pin_level
        byte[] samGpioSetPin = new byte[] {
            (byte) 0x10, (byte) 0xB5, (byte) 0x02, (byte) 0x49, (byte) 0x0A, (byte) 0x68, (byte) 0x10, (byte) 0xBD
        };
        list.add(new AtmelLibrarySignature(
                "atmel.asf.gpio_set_pin_level", "ATMEL_START_ASF", "GPIO", "gpio_set_pin_level",
                "ARM_THUMB", "SAMD", "ARM_GCC", "-O2", "hal_gpio.c", DEFAULT_SOURCE_DIGEST,
                samGpioSetPin, allSpecified(samGpioSetPin.length)));

        // 4. FreeRTOS (SAM Cortex-M and AVR)
        // vTaskStartScheduler (SAM)
        byte[] samTaskStartSchedulerPattern = new byte[] {
            (byte) 0x80, (byte) 0xB5, (byte) 0x00, (byte) 0x20, (byte) 0x00, (byte) 0xF0, (byte) 0x00, (byte) 0xF8
        };
        byte[] samTaskStartSchedulerMask = new byte[] {
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00
        };
        list.add(new AtmelLibrarySignature(
                "freertos.tasks.vTaskStartScheduler", "FREERTOS", "TASKS", "vTaskStartScheduler",
                "ARM_THUMB", "ANY", "ARM_GCC", "-O2", "tasks.c", DEFAULT_SOURCE_DIGEST,
                samTaskStartSchedulerPattern, samTaskStartSchedulerMask));

        // xTaskCreate (SAM)
        byte[] samTaskCreate = new byte[] {
            (byte) 0x2D, (byte) 0xE9, (byte) 0xF0, (byte) 0x41, (byte) 0x85, (byte) 0xB0, (byte) 0x00, (byte) 0x20
        };
        list.add(new AtmelLibrarySignature(
                "freertos.tasks.xTaskCreate", "FREERTOS", "TASKS", "xTaskCreate",
                "ARM_THUMB", "ANY", "ARM_GCC", "-O2", "tasks.c", DEFAULT_SOURCE_DIGEST,
                samTaskCreate, allSpecified(samTaskCreate.length)));

        // vTaskDelay (SAM)
        byte[] samTaskDelay = new byte[] {
            (byte) 0x10, (byte) 0xB5, (byte) 0x04, (byte) 0x46, (byte) 0x00, (byte) 0x28, (byte) 0x02, (byte) 0xD0
        };
        list.add(new AtmelLibrarySignature(
                "freertos.tasks.vTaskDelay", "FREERTOS", "TASKS", "vTaskDelay",
                "ARM_THUMB", "ANY", "ARM_GCC", "-O2", "tasks.c", DEFAULT_SOURCE_DIGEST,
                samTaskDelay, allSpecified(samTaskDelay.length)));

        // xQueueGenericCreate (SAM)
        byte[] samQueueCreate = new byte[] {
            (byte) 0x70, (byte) 0xB5, (byte) 0x04, (byte) 0x46, (byte) 0x0D, (byte) 0x46, (byte) 0x00, (byte) 0x20
        };
        list.add(new AtmelLibrarySignature(
                "freertos.queue.xQueueGenericCreate", "FREERTOS", "QUEUE", "xQueueGenericCreate",
                "ARM_THUMB", "ANY", "ARM_GCC", "-O2", "queue.c", DEFAULT_SOURCE_DIGEST,
                samQueueCreate, allSpecified(samQueueCreate.length)));

        // vTaskStartScheduler (AVR8)
        byte[] avrTaskStartSchedulerPattern = new byte[] {
            (byte) 0x0E, (byte) 0x94, (byte) 0x00, (byte) 0x00, (byte) 0xF8, (byte) 0x94, (byte) 0x00, (byte) 0x00
        };
        byte[] avrTaskStartSchedulerMask = new byte[] {
            (byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0x00
        };
        list.add(new AtmelLibrarySignature(
                "freertos.avr.vTaskStartScheduler", "FREERTOS", "TASKS", "vTaskStartScheduler",
                "AVR8", "ANY", "AVR_GCC", "-Os", "port.c", DEFAULT_SOURCE_DIGEST,
                avrTaskStartSchedulerPattern, avrTaskStartSchedulerMask));

        return new AtmelSignaturePack(
                "atmel-builtin-pack",
                "2026.10",
                List.of(
                        "ATmega", "ATtiny", "AVR-DA", "AVR-DB", "AVR-DD",
                        "SAMD", "SAME", "SAMS", "SAMV", "SAML", "SAMC", "SAM3"),
                list);
    }

    private static byte[] allSpecified(int length) {
        byte[] mask = new byte[length];
        Arrays.fill(mask, (byte) 0xff);
        return mask;
    }
}
