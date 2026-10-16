package io.github.rezabakhshi.embedra.analyzers.stm8;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * Validated signature payload for STMicroelectronics STM8 microcontrollers (SPL and compiler runtimes).
 */
public record Stm8SignaturePack(
        String packId,
        String version,
        List<String> supportedFamilies,
        List<Stm8LibrarySignature> signatures) {

    private static final String DEFAULT_SOURCE_DIGEST =
            "2967854c80487989641778f78bbb9ca6c7c804643cb71c1a2698fe29defeb047";

    public Stm8SignaturePack {
        Objects.requireNonNull(packId, "packId must not be null");
        Objects.requireNonNull(version, "version must not be null");
        supportedFamilies = List.copyOf(supportedFamilies);
        signatures = signatures.stream()
                .sorted(Comparator.comparing(Stm8LibrarySignature::signatureId))
                .toList();
        if (signatures.isEmpty()
                || new HashSet<>(signatures.stream().map(Stm8LibrarySignature::signatureId).toList()).size()
                        != signatures.size()) {
            throw new IllegalArgumentException("Signature IDs must be non-empty and unique");
        }
    }

    public String identity() {
        return packId + "@" + version;
    }

    /**
     * Creates the authoritative built-in signature pack containing Standard Peripheral Library (SPL)
     * routines and open-source compiler runtimes (SDCC, Cosmic).
     */
    public static Stm8SignaturePack builtin() {
        List<Stm8LibrarySignature> list = new ArrayList<>();

        // 1. STM8 SPL routines
        // GPIO_Init (SDCC)
        byte[] gpioInitSdccPattern = new byte[] {
            (byte) 0x89, (byte) 0x88, 0x7B, 0x03, (byte) 0xA1, 0x00, 0x27, 0x05,
            0x6B, 0x00, (byte) 0x81, (byte) 0x84, (byte) 0x85, (byte) 0x81, (byte) 0x9D, (byte) 0x81
        };
        list.add(new Stm8LibrarySignature(
                "stm8.spl.gpio_init.sdcc", "STM8_SPL", "GPIO", "GPIO_Init",
                "ANY", "SDCC", "-Os", "stm8s_gpio.c", DEFAULT_SOURCE_DIGEST,
                gpioInitSdccPattern, allSpecified(gpioInitSdccPattern.length)));

        // CLK_DeInit (SPL)
        byte[] clkDeInitPattern = new byte[] {
            0x35, 0x01, 0x50, (byte) 0xC0, 0x35, 0x00, 0x50, (byte) 0xC1,
            0x35, (byte) 0xE1, 0x50, (byte) 0xC4, 0x35, 0x00, 0x50, (byte) 0xC5,
            (byte) 0x81, (byte) 0x9D
        };
        list.add(new Stm8LibrarySignature(
                "stm8.spl.clk_deinit", "STM8_SPL", "CLK", "CLK_DeInit",
                "ANY", "SDCC", "-Os", "stm8s_clk.c", DEFAULT_SOURCE_DIGEST,
                clkDeInitPattern, allSpecified(clkDeInitPattern.length)));

        // UART1_Init (SPL)
        byte[] uart1InitPattern = new byte[] {
            0x72, 0x35, 0x00, 0x52, 0x34, 0x72, 0x35, 0x0C, 0x52, 0x35,
            0x72, 0x35, 0x00, 0x52, 0x36, (byte) 0x81
        };
        list.add(new Stm8LibrarySignature(
                "stm8.spl.uart1_init", "STM8_SPL", "UART1", "UART1_Init",
                "ANY", "SDCC", "-Os", "stm8s_uart1.c", DEFAULT_SOURCE_DIGEST,
                uart1InitPattern, allSpecified(uart1InitPattern.length)));

        // TIM1_Cmd (SPL)
        byte[] tim1CmdPattern = new byte[] {
            (byte) 0xA1, 0x00, 0x27, 0x07, 0x72, 0x10, 0x52, 0x50,
            (byte) 0x81, 0x72, 0x11, 0x52, 0x50, (byte) 0x81
        };
        list.add(new Stm8LibrarySignature(
                "stm8.spl.tim1_cmd", "STM8_SPL", "TIM1", "TIM1_Cmd",
                "ANY", "SDCC", "-Os", "stm8s_tim1.c", DEFAULT_SOURCE_DIGEST,
                tim1CmdPattern, allSpecified(tim1CmdPattern.length)));

        // SPI_Init (SPL)
        byte[] spiInitPattern = new byte[] {
            0x72, 0x35, 0x00, 0x52, 0x00, 0x72, 0x35, 0x04, 0x52, 0x01,
            0x72, 0x35, 0x00, 0x52, 0x02, (byte) 0x81
        };
        list.add(new Stm8LibrarySignature(
                "stm8.spl.spi_init", "STM8_SPL", "SPI", "SPI_Init",
                "ANY", "SDCC", "-Os", "stm8s_spi.c", DEFAULT_SOURCE_DIGEST,
                spiInitPattern, allSpecified(spiInitPattern.length)));

        // 2. SDCC compiler runtimes
        // __divsint (SDCC signed integer division)
        byte[] divsintPattern = new byte[] {
            (byte) 0x89, 0x7B, 0x03, 0x26, 0x06, 0x7B, 0x04, 0x27, 0x0A,
            0x62, (byte) 0x85, (byte) 0x81, (byte) 0x85, (byte) 0x81, (byte) 0x80, (byte) 0x81
        };
        list.add(new Stm8LibrarySignature(
                "stm8.runtime.__divsint.sdcc", "SDCC_RUNTIME", "RUNTIME", "__divsint",
                "ANY", "SDCC", "-Os", "_divsint.s", DEFAULT_SOURCE_DIGEST,
                divsintPattern, allSpecified(divsintPattern.length)));

        // __mullong (SDCC long multiplication)
        byte[] mullongPattern = new byte[] {
            (byte) 0x89, (byte) 0x90, (byte) 0x89, 0x7B, 0x07, 0x42,
            (byte) 0x90, 0x1F, 0x01, (byte) 0x90, (byte) 0x85, (byte) 0x85,
            (byte) 0x81, (byte) 0x9D, (byte) 0x81, (byte) 0x81
        };
        list.add(new Stm8LibrarySignature(
                "stm8.runtime.__mullong.sdcc", "SDCC_RUNTIME", "RUNTIME", "__mullong",
                "ANY", "SDCC", "-Os", "_mullong.s", DEFAULT_SOURCE_DIGEST,
                mullongPattern, allSpecified(mullongPattern.length)));

        // __mulint (SDCC integer multiplication)
        byte[] mulintPattern = new byte[] {
            (byte) 0x88, (byte) 0x90, (byte) 0xAE, 0x00, 0x00, 0x7B, 0x04,
            0x42, (byte) 0x84, (byte) 0x81, (byte) 0x9D, (byte) 0x9D,
            (byte) 0x81, (byte) 0x81, (byte) 0x9D, (byte) 0x81
        };
        list.add(new Stm8LibrarySignature(
                "stm8.runtime.__mulint.sdcc", "SDCC_RUNTIME", "RUNTIME", "__mulint",
                "ANY", "SDCC", "-Os", "_mulint.s", DEFAULT_SOURCE_DIGEST,
                mulintPattern, allSpecified(mulintPattern.length)));

        // 3. Cosmic compiler runtimes
        // _switch (Cosmic switch-case table helper)
        byte[] switchPattern = new byte[] {
            0x7B, 0x03, (byte) 0xD1, 0x00, 0x00, 0x27, 0x05, 0x5C,
            0x20, (byte) 0xF7, (byte) 0x81, (byte) 0x9D, (byte) 0x81, (byte) 0x9D, (byte) 0x81, (byte) 0x81
        };
        list.add(new Stm8LibrarySignature(
                "stm8.runtime._switch.cosmic", "COSMIC_RUNTIME", "RUNTIME", "_switch",
                "ANY", "COSMIC", "-Os", "_switch.s", DEFAULT_SOURCE_DIGEST,
                switchPattern, allSpecified(switchPattern.length)));

        // _i_div (Cosmic integer division)
        byte[] idivPattern = new byte[] {
            (byte) 0x89, (byte) 0x90, (byte) 0x89, 0x7B, 0x03, 0x62,
            (byte) 0x90, (byte) 0x85, (byte) 0x85, (byte) 0x81, (byte) 0x9D,
            (byte) 0x81, (byte) 0x9D, (byte) 0x81, (byte) 0x81, (byte) 0x81
        };
        list.add(new Stm8LibrarySignature(
                "stm8.runtime._i_div.cosmic", "COSMIC_RUNTIME", "RUNTIME", "_i_div",
                "ANY", "COSMIC", "-Os", "_idiv.s", DEFAULT_SOURCE_DIGEST,
                idivPattern, allSpecified(idivPattern.length)));

        // _l_mul (Cosmic long multiplication)
        byte[] lmulPattern = new byte[] {
            (byte) 0x89, (byte) 0x90, (byte) 0x89, 0x7B, 0x05, 0x42,
            (byte) 0x90, (byte) 0x85, (byte) 0x85, (byte) 0x81, (byte) 0x9D,
            (byte) 0x81, (byte) 0x9D, (byte) 0x81, (byte) 0x81, (byte) 0x81
        };
        list.add(new Stm8LibrarySignature(
                "stm8.runtime._l_mul.cosmic", "COSMIC_RUNTIME", "RUNTIME", "_l_mul",
                "ANY", "COSMIC", "-Os", "_lmul.s", DEFAULT_SOURCE_DIGEST,
                lmulPattern, allSpecified(lmulPattern.length)));

        return new Stm8SignaturePack(
                "stm8.spl.runtime.signatures",
                "1.0.0",
                List.of("STM8S", "STM8L", "STM8A", "STM8T", "ANY"),
                list);
    }

    private static byte[] allSpecified(int length) {
        byte[] mask = new byte[length];
        Arrays.fill(mask, (byte) 0xFF);
        return mask;
    }
}
