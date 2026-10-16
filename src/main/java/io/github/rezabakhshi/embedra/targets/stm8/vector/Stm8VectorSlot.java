package io.github.rezabakhshi.embedra.targets.stm8.vector;

import java.util.Locale;

/**
 * Standard 32 interrupt vector table slots for STMicroelectronics STM8 8-bit MCUs (RM0016 / RM0031).
 */
public enum Stm8VectorSlot {
    SLOT_0_RESET(0, "RESET", "Reset vector (non-maskable)"),
    SLOT_1_TRAP(1, "TRAP", "Software trap interrupt"),
    SLOT_2_TLI(2, "TLI", "Top-level external interrupt pin"),
    SLOT_3_AWU(3, "AWU", "Auto wake-up from halt mode"),
    SLOT_4_CLK(4, "CLK", "Clock controller and CSS interrupt"),
    SLOT_5_EXTI0(5, "EXTI0", "Port A external interrupt"),
    SLOT_6_EXTI1(6, "EXTI1", "Port B external interrupt"),
    SLOT_7_EXTI2(7, "EXTI2", "Port C external interrupt"),
    SLOT_8_EXTI3(8, "EXTI3", "Port D external interrupt"),
    SLOT_9_EXTI4(9, "EXTI4", "Port E external interrupt"),
    SLOT_10_CAN_RX_OR_AES_OR_TOUCH(10, "CAN_RX_OR_AES_OR_TOUCH", "CAN RX (STM8S/AF) / AES (STM8L) / Touch (STM8T)"),
    SLOT_11_CAN_TX_OR_DMA1_CH0_1(11, "CAN_TX_OR_DMA1_CH0_1", "CAN TX (STM8S/AF) / DMA1 Ch0/1 (STM8L)"),
    SLOT_12_SPI_OR_DMA1_CH2_3(12, "SPI_OR_DMA1_CH2_3", "SPI (STM8S/AF) / DMA1 Ch2/3 (STM8L)"),
    SLOT_13_TIM1_UPD_OR_RTC(13, "TIM1_UPD_OR_RTC", "TIM1 Update (STM8S/AF) / RTC (STM8L)"),
    SLOT_14_TIM1_CC_OR_EXTIF(14, "TIM1_CC_OR_EXTIF", "TIM1 Capture/Compare (STM8S/AF) / EXTIF (STM8L)"),
    SLOT_15_TIM2_UPD_OR_EXTIB(15, "TIM2_UPD_OR_EXTIB", "TIM2 Update (STM8S/AF) / EXTIB (STM8L)"),
    SLOT_16_TIM2_CC_OR_EXTID(16, "TIM2_CC_OR_EXTID", "TIM2 Capture/Compare (STM8S/AF) / EXTID (STM8L)"),
    SLOT_17_TIM3_UPD_OR_USART1_TX(17, "TIM3_UPD_OR_USART1_TX", "TIM3 Update (STM8S/AF) / USART1 TX (STM8L)"),
    SLOT_18_TIM3_CC_OR_USART1_RX(18, "TIM3_CC_OR_USART1_RX", "TIM3 Capture/Compare (STM8S/AF) / USART1 RX (STM8L)"),
    SLOT_19_UART1_TX_OR_I2C1_SPI1(19, "UART1_TX_OR_I2C1_SPI1", "UART1 TX (STM8S/AF) / I2C1, SPI1 (STM8L)"),
    SLOT_20_UART1_RX_OR_TIM1_UPD(20, "UART1_RX_OR_TIM1_UPD", "UART1 RX (STM8S/AF) / TIM1 Update (STM8L)"),
    SLOT_21_I2C_OR_TIM1_CC(21, "I2C_OR_TIM1_CC", "I2C (STM8S/AF) / TIM1 Capture/Compare (STM8L)"),
    SLOT_22_UART2_3_TX_OR_TIM2_UPD(22, "UART2_3_TX_OR_TIM2_UPD", "UART2/3 TX (STM8S/AF) / TIM2 Update (STM8L)"),
    SLOT_23_UART2_3_RX_OR_TIM2_CC(23, "UART2_3_RX_OR_TIM2_CC", "UART2/3 RX (STM8S/AF) / TIM2 Capture/Compare (STM8L)"),
    SLOT_24_ADC_OR_TIM3_UPD(24, "ADC_OR_TIM3_UPD", "ADC1/2 (STM8S/AF) / TIM3 Update (STM8L)"),
    SLOT_25_TIM4_UPD_OR_TIM3_CC(25, "TIM4_UPD_OR_TIM3_CC", "TIM4 Update (STM8S/AF) / TIM3 Capture/Compare (STM8L)"),
    SLOT_26_FLASH_OR_USART2_3_TX(26, "FLASH_OR_USART2_3_TX", "Flash EOP (STM8S/AF) / USART2/3 TX (STM8L)"),
    SLOT_27_RESERVED_OR_USART2_3_RX(27, "RESERVED_OR_USART2_3_RX", "Reserved (STM8S/AF) / USART2/3 RX (STM8L)"),
    SLOT_28_RESERVED_OR_ADC1_COMP(28, "RESERVED_OR_ADC1_COMP", "Reserved (STM8S/AF) / ADC1, COMP (STM8L)"),
    SLOT_29_RESERVED_OR_LCD(29, "RESERVED_OR_LCD", "Reserved (STM8S/AF) / LCD driver (STM8L)"),
    SLOT_30_RESERVED_OR_TIM4_UPD(30, "RESERVED_OR_TIM4_UPD", "Reserved (STM8S/AF) / TIM4 Update (STM8L)"),
    SLOT_31_RESERVED_OR_SPI2(31, "RESERVED_OR_SPI2", "Reserved (STM8S/AF) / SPI2 (STM8L)");

    private final int slotIndex;

    private final String canonicalName;

    private final String description;

    Stm8VectorSlot(int slotIndex, String canonicalName, String description) {
        this.slotIndex = slotIndex;
        this.canonicalName = canonicalName;
        this.description = description;
    }

    public int slotIndex() {
        return slotIndex;
    }

    public String canonicalName() {
        return canonicalName;
    }

    public String description() {
        return description;
    }

    public long offset() {
        return 0x008000L + (slotIndex * 4L);
    }

    public static Stm8VectorSlot fromIndex(int index) {
        if (index < 0 || index >= values().length) {
            throw new IllegalArgumentException("Invalid vector slot index: " + index);
        }
        return values()[index];
    }

    public String handlerLabelForFamily(String family) {
        String f = family == null ? "STM8S" : family.trim().toUpperCase(Locale.ROOT);
        if (f.startsWith("STM8L") || f.equals("STM8AL")) {
            return handlerLabelStm8l();
        }
        if (f.equals("STM8T")) {
            return handlerLabelStm8t();
        }
        return handlerLabelStm8s();
    }

    private String handlerLabelStm8s() {
        return switch (slotIndex) {
            case 0 -> "Reset_Handler";
            case 1 -> "TRAP_IRQHandler";
            case 2 -> "TLI_IRQHandler";
            case 3 -> "AWU_IRQHandler";
            case 4 -> "CLK_IRQHandler";
            case 5 -> "EXTI0_IRQHandler";
            case 6 -> "EXTI1_IRQHandler";
            case 7 -> "EXTI2_IRQHandler";
            case 8 -> "EXTI3_IRQHandler";
            case 9 -> "EXTI4_IRQHandler";
            case 10 -> "CAN_RX_IRQHandler";
            case 11 -> "CAN_TX_IRQHandler";
            case 12 -> "SPI_IRQHandler";
            case 13 -> "TIM1_UPD_OVF_TRG_BRK_IRQHandler";
            case 14 -> "TIM1_CAP_COM_IRQHandler";
            case 15 -> "TIM2_UPD_OVF_BRK_IRQHandler";
            case 16 -> "TIM2_CAP_COM_IRQHandler";
            case 17 -> "TIM3_UPD_OVF_BRK_IRQHandler";
            case 18 -> "TIM3_CAP_COM_IRQHandler";
            case 19 -> "UART1_TX_IRQHandler";
            case 20 -> "UART1_RX_IRQHandler";
            case 21 -> "I2C_IRQHandler";
            case 22 -> "UART2_3_TX_IRQHandler";
            case 23 -> "UART2_3_RX_IRQHandler";
            case 24 -> "ADC1_2_IRQHandler";
            case 25 -> "TIM4_UPD_OVF_IRQHandler";
            case 26 -> "FLASH_IRQHandler";
            default -> "Reserved" + slotIndex + "_IRQHandler";
        };
    }

    private String handlerLabelStm8l() {
        return switch (slotIndex) {
            case 0 -> "Reset_Handler";
            case 1 -> "TRAP_IRQHandler";
            case 2 -> "TLI_IRQHandler";
            case 3 -> "AWU_IRQHandler";
            case 4 -> "CLK_CSS_IRQHandler";
            case 5 -> "EXTI0_IRQHandler";
            case 6 -> "EXTI1_IRQHandler";
            case 7 -> "EXTI2_IRQHandler";
            case 8 -> "EXTI3_IRQHandler";
            case 9 -> "EXTI4_IRQHandler";
            case 10 -> "AES_IRQHandler";
            case 11 -> "DMA1_CH0_1_IRQHandler";
            case 12 -> "DMA1_CH2_3_IRQHandler";
            case 13 -> "RTC_IRQHandler";
            case 14 -> "EXTIF_PVD_IRQHandler";
            case 15 -> "EXTIB_IRQHandler";
            case 16 -> "EXTID_IRQHandler";
            case 17 -> "USART1_TX_IRQHandler";
            case 18 -> "USART1_RX_IRQHandler";
            case 19 -> "I2C1_SPI1_IRQHandler";
            case 20 -> "TIM1_UPD_OVF_TRG_IRQHandler";
            case 21 -> "TIM1_CAP_COM_IRQHandler";
            case 22 -> "TIM2_UPD_OVF_TRG_IRQHandler";
            case 23 -> "TIM2_CAP_COM_IRQHandler";
            case 24 -> "TIM3_UPD_OVF_TRG_IRQHandler";
            case 25 -> "TIM3_CAP_COM_IRQHandler";
            case 26 -> "USART2_3_TX_IRQHandler";
            case 27 -> "USART2_3_RX_IRQHandler";
            case 28 -> "ADC1_COMP_IRQHandler";
            case 29 -> "LCD_IRQHandler";
            case 30 -> "TIM4_UPD_OVF_IRQHandler";
            case 31 -> "SPI2_IRQHandler";
            default -> "Reserved" + slotIndex + "_IRQHandler";
        };
    }

    private String handlerLabelStm8t() {
        return switch (slotIndex) {
            case 0 -> "Reset_Handler";
            case 1 -> "TRAP_IRQHandler";
            case 2 -> "TLI_IRQHandler";
            case 3 -> "AWU_IRQHandler";
            case 4 -> "CLK_IRQHandler";
            case 5 -> "EXTI0_IRQHandler";
            case 6 -> "EXTI1_IRQHandler";
            case 7 -> "EXTI2_IRQHandler";
            case 8 -> "EXTI3_IRQHandler";
            case 9 -> "EXTI4_IRQHandler";
            case 10 -> "TOUCH_IRQHandler";
            case 12 -> "SPI_IRQHandler";
            case 13 -> "TIM1_UPD_OVF_IRQHandler";
            case 14 -> "TIM1_CAP_COM_IRQHandler";
            case 15 -> "TIM2_UPD_OVF_IRQHandler";
            case 16 -> "TIM2_CAP_COM_IRQHandler";
            case 21 -> "I2C_IRQHandler";
            case 25 -> "TIM4_UPD_OVF_IRQHandler";
            case 26 -> "FLASH_IRQHandler";
            default -> "Reserved" + slotIndex + "_IRQHandler";
        };
    }
}
