package io.github.rezabakhshi.embedra.targets.nordic.peripheral;

import java.util.ArrayList;
import java.util.List;

/**
 * Authoritative built-in peripheral register packs for Nordic Semiconductor nRF51, nRF52,
 * nRF53, nRF54, and nRF91 series.
 */
public final class NordicDefaultPacks {

    public static final String SCHEMA_ID = "urn:embedra:schema:nordic-peripheral-pack:1";

    private NordicDefaultPacks() {
    }

    public static NordicPeripheralPack createNrf51Pack() {
        List<NordicPeripheral> periphs = new ArrayList<>();
        periphs.add(createClockPowerPeripheral(0x40000000L, "CLOCK_POWER", "Clock and Power Management"));
        periphs.add(createRadioPeripheral(0x40001000L, "RADIO", false));
        periphs.add(createUartPeripheral(0x40002000L, "UART0", false));
        periphs.add(createSpiPeripheral(0x40003000L, "SPI0", false));
        periphs.add(createTwiPeripheral(0x40004000L, "TWI0", false));
        periphs.add(createGpiotePeripheral(0x40006000L, "GPIOTE"));
        periphs.add(createTimerPeripheral(0x40008000L, "TIMER0"));
        periphs.add(createTimerPeripheral(0x40009000L, "TIMER1"));
        periphs.add(createTimerPeripheral(0x4000A000L, "TIMER2"));
        periphs.add(createRtcPeripheral(0x4000B000L, "RTC0"));
        periphs.add(createTempPeripheral(0x4000C000L, "TEMP"));
        periphs.add(createRngPeripheral(0x4000D000L, "RNG"));
        periphs.add(createWdtPeripheral(0x40010000L, "WDT"));
        periphs.add(createRtcPeripheral(0x40011000L, "RTC1"));
        periphs.add(createNvmcPeripheral(0x4001E000L, "NVMC"));

        return new NordicPeripheralPack(
            "nrf51-peripherals", "nRF51", SCHEMA_ID,
            "Nordic Semiconductor nRF51 Series Reference Manual", periphs);
    }

    public static NordicPeripheralPack createNrf52Pack() {
        List<NordicPeripheral> periphs = new ArrayList<>();
        periphs.add(createClockPowerPeripheral(0x40000000L, "CLOCK", "Clock Management"));
        periphs.add(createRadioPeripheral(0x40001000L, "RADIO", true));
        periphs.add(createUartPeripheral(0x40002000L, "UARTE0", true));
        periphs.add(createSpiPeripheral(0x40003000L, "SPIM0", true));
        periphs.add(createTwiPeripheral(0x40004000L, "TWIM0", true));
        periphs.add(createGpiotePeripheral(0x40006000L, "GPIOTE"));
        periphs.add(createTimerPeripheral(0x40008000L, "TIMER0"));
        periphs.add(createTimerPeripheral(0x40009000L, "TIMER1"));
        periphs.add(createTimerPeripheral(0x4000A000L, "TIMER2"));
        periphs.add(createRtcPeripheral(0x4000B000L, "RTC0"));
        periphs.add(createTempPeripheral(0x4000C000L, "TEMP"));
        periphs.add(createRngPeripheral(0x4000D000L, "RNG"));
        periphs.add(createWdtPeripheral(0x40010000L, "WDT"));
        periphs.add(createRtcPeripheral(0x40011000L, "RTC1"));
        periphs.add(createNvmcPeripheral(0x4001E000L, "NVMC"));
        // Hardware crypto accelerator CC310 on nRF52840
        periphs.add(NordicCryptoCellDefinition.createCc310Peripheral());

        return new NordicPeripheralPack(
            "nrf52-peripherals", "nRF52", SCHEMA_ID,
            "Nordic Semiconductor nRF52 Series Product Specification", periphs);
    }

    public static NordicPeripheralPack createNrf53Pack() {
        List<NordicPeripheral> periphs = new ArrayList<>();
        periphs.add(createSpuPeripheral(0x50003000L, "SPU"));
        periphs.add(createClockPowerPeripheral(0x50005000L, "CLOCK_SECURE", "Clock Management (Secure)"));
        periphs.add(createUartPeripheral(0x50008000L, "UARTE0_SECURE", true));
        periphs.add(createGpiotePeripheral(0x5000D000L, "GPIOTE0_SECURE"));
        periphs.add(createTimerPeripheral(0x5000F000L, "TIMER0_SECURE"));
        periphs.add(createRtcPeripheral(0x50014000L, "RTC0_SECURE"));
        periphs.add(createWdtPeripheral(0x50018000L, "WDT0_SECURE"));
        periphs.add(createDppiPeripheral(0x50025000L, "DPPI_SECURE"));
        periphs.add(createNvmcPeripheral(0x50039000L, "NVMC_SECURE"));

        // Non-Secure Aliases / Peripherals
        periphs.add(createRadioPeripheral(0x40001000L, "RADIO", true));
        periphs.add(createUartPeripheral(0x40008000L, "UARTE0", true));
        periphs.add(createSpiPeripheral(0x40009000L, "SPIM0", true));
        periphs.add(createTwiPeripheral(0x4000A000L, "TWIM0", true));
        periphs.add(createTimerPeripheral(0x4000F000L, "TIMER0"));
        periphs.add(createRtcPeripheral(0x40014000L, "RTC0"));
        periphs.add(createDppiPeripheral(0x40025000L, "DPPI"));
        periphs.add(createTempPeripheral(0x4000C000L, "TEMP"));
        periphs.add(createRngPeripheral(0x4000D000L, "RNG"));

        // Hardware crypto accelerator CC312
        periphs.add(NordicCryptoCellDefinition.createCc312Peripheral());

        return new NordicPeripheralPack(
            "nrf53-peripherals", "nRF53", SCHEMA_ID,
            "Nordic Semiconductor nRF5340 Product Specification", periphs);
    }

    public static NordicPeripheralPack createNrf54Pack() {
        List<NordicPeripheral> periphs = new ArrayList<>();
        periphs.add(createSpuPeripheral(0x50003000L, "SPU"));
        periphs.add(createClockPowerPeripheral(0x50005000L, "CLOCK", "Clock Management"));
        periphs.add(createRadioPeripheral(0x50001000L, "RADIO", true));
        periphs.add(createUartPeripheral(0x50002000L, "UARTE0", true));
        periphs.add(createSpiPeripheral(0x50003000L, "SPIM0", true));
        periphs.add(createTwiPeripheral(0x50004000L, "TWIM0", true));
        periphs.add(createGpiotePeripheral(0x50006000L, "GPIOTE"));
        periphs.add(createTimerPeripheral(0x50008000L, "TIMER0"));
        periphs.add(createRtcPeripheral(0x5000B000L, "RTC0"));
        periphs.add(createTempPeripheral(0x5000C000L, "TEMP"));
        periphs.add(createRngPeripheral(0x5000D000L, "RNG"));
        periphs.add(createWdtPeripheral(0x50010000L, "WDT"));
        periphs.add(createDppiPeripheral(0x50025000L, "DPPI"));
        periphs.add(createNvmcPeripheral(0x50039000L, "RRAMC"));

        return new NordicPeripheralPack(
            "nrf54-peripherals", "nRF54", SCHEMA_ID,
            "Nordic Semiconductor nRF54 Series Product Specification", periphs);
    }

    public static NordicPeripheralPack createNrf91Pack() {
        List<NordicPeripheral> periphs = new ArrayList<>();
        periphs.add(createSpuPeripheral(0x50003000L, "SPU"));
        periphs.add(createClockPowerPeripheral(0x50005000L, "CLOCK_SECURE", "Clock Management (Secure)"));
        periphs.add(createUartPeripheral(0x50008000L, "UARTE0_SECURE", true));
        periphs.add(createGpiotePeripheral(0x5000D000L, "GPIOTE0_SECURE"));
        periphs.add(createTimerPeripheral(0x5000F000L, "TIMER0_SECURE"));
        periphs.add(createRtcPeripheral(0x50014000L, "RTC0_SECURE"));
        periphs.add(createWdtPeripheral(0x50018000L, "WDT0_SECURE"));
        periphs.add(createDppiPeripheral(0x50025000L, "DPPI_SECURE"));
        periphs.add(createNvmcPeripheral(0x50039000L, "NVMC_SECURE"));

        // Non-Secure Aliases
        periphs.add(createUartPeripheral(0x40008000L, "UARTE0", true));
        periphs.add(createSpiPeripheral(0x40009000L, "SPIM0", true));
        periphs.add(createTwiPeripheral(0x4000A000L, "TWIM0", true));
        periphs.add(createTimerPeripheral(0x4000F000L, "TIMER0"));
        periphs.add(createRtcPeripheral(0x40014000L, "RTC0"));
        periphs.add(createDppiPeripheral(0x40025000L, "DPPI"));

        // Hardware crypto accelerator CC312
        periphs.add(NordicCryptoCellDefinition.createCc312Peripheral());

        return new NordicPeripheralPack(
            "nrf91-peripherals", "nRF91", SCHEMA_ID,
            "Nordic Semiconductor nRF9160 Product Specification", periphs);
    }

    public static NordicPeripheral createClockPowerPeripheral(long base, String name, String desc) {
        List<NordicRegister> regs = new ArrayList<>();
        regs.add(reg("TASKS_HFCLKSTART", base, 0x000L, "Start HFCLK clock source"));
        regs.add(reg("TASKS_HFCLKSTOP", base, 0x004L, "Stop HFCLK clock source"));
        regs.add(reg("TASKS_LFCLKSTART", base, 0x008L, "Start LFCLK clock source"));
        regs.add(reg("TASKS_LFCLKSTOP", base, 0x00CL, "Stop LFCLK clock source"));
        regs.add(reg("EVENTS_HFCLKSTARTED", base, 0x100L, "HFCLK oscillator started"));
        regs.add(reg("EVENTS_LFCLKSTARTED", base, 0x104L, "LFCLK oscillator started"));
        regs.add(reg("RESETREAS", base, 0x400L, "Reset Reason",
            List.of(NordicBitField.singleBit("RESETPIN", 0, "R/W", "Reset from pin assertion"),
                    NordicBitField.singleBit("DOG", 1, "R/W", "Reset from watchdog timeout"),
                    NordicBitField.singleBit("SREQ", 2, "R/W", "Reset from AIRCR.SYSRESETREQ"),
                    NordicBitField.singleBit("LOCKUP", 3, "R/W", "Reset from CPU lockup"))));
        regs.add(reg("SYSTEMOFF", base, 0x500L, "Enter System OFF Power Mode",
            List.of(NordicBitField.singleBit("ENTER", 0, "W", "Enter system off"))));
        regs.add(reg("LFCLKSRC", base, 0x518L, "Clock Source for the LFCLK",
            List.of(new NordicBitField("SRC", 0, 2, 0x03L, "R/W", "0=RC, 1=XTAL, 2=Synth"))));

        return new NordicPeripheral(name, base, base + 0x1000L, desc, regs);
    }

    public static NordicPeripheral createRadioPeripheral(long base, String name, boolean easyDma) {
        List<NordicRegister> regs = new ArrayList<>();
        regs.add(reg("TASKS_TXEN", base, 0x000L, "Enable Radio in TX mode"));
        regs.add(reg("TASKS_RXEN", base, 0x004L, "Enable Radio in RX mode"));
        regs.add(reg("TASKS_START", base, 0x008L, "Start Radio operation"));
        regs.add(reg("TASKS_STOP", base, 0x00CL, "Stop Radio operation"));
        regs.add(reg("TASKS_DISABLE", base, 0x010L, "Disable Radio"));
        regs.add(reg("EVENTS_READY", base, 0x100L, "Radio has ramped up and is ready"));
        regs.add(reg("EVENTS_ADDRESS", base, 0x104L, "Address sent or received"));
        regs.add(reg("EVENTS_PAYLOAD", base, 0x108L, "Payload sent or received"));
        regs.add(reg("EVENTS_END", base, 0x10CL, "Packet transmission/reception complete"));
        regs.add(reg("EVENTS_DISABLED", base, 0x110L, "Radio has ramped down"));
        regs.add(reg("SHORTS", base, 0x200L, "Shortcuts between local events and tasks"));
        regs.add(reg("INTENSET", base, 0x304L, "Enable interrupt"));
        regs.add(reg("INTENCLR", base, 0x308L, "Disable interrupt"));
        regs.add(reg("CRCSTATUS", base, 0x400L, "CRC Status",
            List.of(NordicBitField.singleBit("CRCSTATUS", 0, "R", "CRC status of packet received"))));

        if (easyDma) {
            regs.add(dmaReg("PACKETPTR", base, 0x504L, "Packet Data Pointer (EasyDMA)", NordicEasyDmaType.PTR));
        } else {
            regs.add(reg("PACKETPTR", base, 0x504L, "Packet Data Pointer"));
        }

        regs.add(reg("FREQUENCY", base, 0x508L, "Frequency in 2.4 GHz Band",
            List.of(new NordicBitField("FREQ", 0, 7, 0x7FL, "R/W", "Channel frequency 2400 + FREQ MHz"))));
        regs.add(reg("TXPOWER", base, 0x50CL, "Output Power",
            List.of(new NordicBitField("TXPOWER", 0, 8, 0xFFL, "R/W", "RADIO transmit power dBm"))));
        regs.add(reg("MODE", base, 0x510L, "Data Rate and Modulation",
            List.of(new NordicBitField("MODE", 0, 4, 0x0FL, "R/W",
                "0=1Mbps BLE, 1=2Mbps BLE, 2=250kbps, 3=BLE Long Range"))));
        regs.add(reg("PCNF0", base, 0x514L, "Packet Configuration Register 0"));
        regs.add(reg("PCNF1", base, 0x518L, "Packet Configuration Register 1"));

        return new NordicPeripheral(name, base, base + 0x1000L, "2.4 GHz Multi-Protocol Radio", regs);
    }

    public static NordicPeripheral createUartPeripheral(long base, String name, boolean easyDma) {
        List<NordicRegister> regs = new ArrayList<>();
        regs.add(reg("TASKS_STARTRX", base, 0x000L, "Start UART receiver"));
        regs.add(reg("TASKS_STOPRX", base, 0x004L, "Stop UART receiver"));
        regs.add(reg("TASKS_STARTTX", base, 0x008L, "Start UART transmitter"));
        regs.add(reg("TASKS_STOPTX", base, 0x00CL, "Stop UART transmitter"));
        regs.add(reg("EVENTS_CTS", base, 0x100L, "CTS activated"));
        regs.add(reg("EVENTS_NCTS", base, 0x104L, "CTS deactivated"));
        regs.add(reg("EVENTS_RXDRDY", base, 0x108L, "Data received in RXD"));
        regs.add(reg("EVENTS_ENDRX", base, 0x110L, "Receive buffer complete"));
        regs.add(reg("EVENTS_TXDRDY", base, 0x11CL, "Data sent from TXD"));
        regs.add(reg("EVENTS_ENDTX", base, 0x120L, "Last TX byte transmitted"));
        regs.add(reg("EVENTS_ERROR", base, 0x124L, "Error detected"));
        regs.add(reg("INTENSET", base, 0x304L, "Enable interrupt"));
        regs.add(reg("INTENCLR", base, 0x308L, "Disable interrupt"));
        regs.add(reg("ERRORSRC", base, 0x480L, "Error Source",
            List.of(NordicBitField.singleBit("OVERRUN", 0, "R/W", "Overrun error"),
                    NordicBitField.singleBit("PARITY", 1, "R/W", "Parity error"),
                    NordicBitField.singleBit("FRAMING", 2, "R/W", "Framing error"),
                    NordicBitField.singleBit("BREAK", 3, "R/W", "Break condition"))));
        regs.add(reg("ENABLE", base, 0x500L, "Enable UART",
            List.of(new NordicBitField("ENABLE", 0, 4, 0x0FL, "R/W", "4=Enable UART, 8=Enable UARTE"))));
        regs.add(reg("BAUDRATE", base, 0x524L, "Baud Rate"));

        if (easyDma) {
            regs.add(dmaReg("RXD_PTR", base, 0x534L, "RX Buffer Address", NordicEasyDmaType.PTR));
            regs.add(dmaReg("RXD_MAXCNT", base, 0x538L, "Maximum RX Bytes", NordicEasyDmaType.MAXCNT));
            regs.add(dmaReg("RXD_AMOUNT", base, 0x53CL, "Received Bytes", NordicEasyDmaType.AMOUNT));
            regs.add(dmaReg("TXD_PTR", base, 0x544L, "TX Buffer Address", NordicEasyDmaType.PTR));
            regs.add(dmaReg("TXD_MAXCNT", base, 0x548L, "Maximum TX Bytes", NordicEasyDmaType.MAXCNT));
            regs.add(dmaReg("TXD_AMOUNT", base, 0x54CL, "Transmitted Bytes", NordicEasyDmaType.AMOUNT));
        }

        regs.add(reg("CONFIG", base, 0x56CL, "Configuration Register",
            List.of(NordicBitField.singleBit("HWFC", 0, "R/W", "Hardware flow control enable"),
                    new NordicBitField("PARITY", 1, 3, 0x0EL, "R/W", "Parity selection"))));

        return new NordicPeripheral(name, base, base + 0x1000L, "Universal Asynchronous Receiver/Transmitter", regs);
    }

    public static NordicPeripheral createSpiPeripheral(long base, String name, boolean easyDma) {
        List<NordicRegister> regs = new ArrayList<>();
        regs.add(reg("TASKS_START", base, 0x010L, "Start SPI transaction"));
        regs.add(reg("TASKS_STOP", base, 0x014L, "Stop SPI transaction"));
        regs.add(reg("EVENTS_STOPPED", base, 0x104L, "SPI transaction stopped"));
        regs.add(reg("EVENTS_ENDRX", base, 0x110L, "End of RXD buffer reached"));
        regs.add(reg("EVENTS_END", base, 0x118L, "End of RXD and TXD transactions"));
        regs.add(reg("EVENTS_ENDTX", base, 0x120L, "End of TXD buffer reached"));
        regs.add(reg("INTENSET", base, 0x304L, "Enable interrupt"));
        regs.add(reg("INTENCLR", base, 0x308L, "Disable interrupt"));
        regs.add(reg("ENABLE", base, 0x500L, "Enable SPIM",
            List.of(new NordicBitField("ENABLE", 0, 4, 0x0FL, "R/W", "7=Enable SPIM"))));
        regs.add(reg("FREQUENCY", base, 0x524L, "SPI Frequency"));

        if (easyDma) {
            regs.add(dmaReg("RXD_PTR", base, 0x534L, "RX Buffer Address", NordicEasyDmaType.PTR));
            regs.add(dmaReg("RXD_MAXCNT", base, 0x538L, "Maximum RX Bytes", NordicEasyDmaType.MAXCNT));
            regs.add(dmaReg("RXD_AMOUNT", base, 0x53CL, "Received Bytes", NordicEasyDmaType.AMOUNT));
            regs.add(dmaReg("RXD_LIST", base, 0x540L, "RX EasyDMA List Type", NordicEasyDmaType.LIST));
            regs.add(dmaReg("TXD_PTR", base, 0x544L, "TX Buffer Address", NordicEasyDmaType.PTR));
            regs.add(dmaReg("TXD_MAXCNT", base, 0x548L, "Maximum TX Bytes", NordicEasyDmaType.MAXCNT));
            regs.add(dmaReg("TXD_AMOUNT", base, 0x54CL, "Transmitted Bytes", NordicEasyDmaType.AMOUNT));
            regs.add(dmaReg("TXD_LIST", base, 0x550L, "TX EasyDMA List Type", NordicEasyDmaType.LIST));
        }

        regs.add(reg("CONFIG", base, 0x554L, "SPI Configuration Register",
            List.of(NordicBitField.singleBit("ORDER", 0, "R/W", "0=MSB first, 1=LSB first"),
                    NordicBitField.singleBit("CPHA", 1, "R/W", "0=Leading edge, 1=Trailing edge"),
                    NordicBitField.singleBit("CPOL", 2, "R/W", "0=Active high, 1=Active low"))));

        return new NordicPeripheral(name, base, base + 0x1000L, "Serial Peripheral Interface Master", regs);
    }

    public static NordicPeripheral createTwiPeripheral(long base, String name, boolean easyDma) {
        List<NordicRegister> regs = new ArrayList<>();
        regs.add(reg("TASKS_STARTRX", base, 0x000L, "Start TWI receive sequence"));
        regs.add(reg("TASKS_STARTTX", base, 0x008L, "Start TWI transmit sequence"));
        regs.add(reg("TASKS_STOP", base, 0x014L, "Stop TWI transaction"));
        regs.add(reg("EVENTS_STOPPED", base, 0x104L, "TWI stopped"));
        regs.add(reg("EVENTS_ERROR", base, 0x124L, "Error detected"));
        regs.add(reg("INTENSET", base, 0x304L, "Enable interrupt"));
        regs.add(reg("INTENCLR", base, 0x308L, "Disable interrupt"));
        regs.add(reg("ENABLE", base, 0x500L, "Enable TWIM",
            List.of(new NordicBitField("ENABLE", 0, 4, 0x0FL, "R/W", "6=Enable TWIM"))));
        regs.add(reg("FREQUENCY", base, 0x524L, "TWI Bus Clock Frequency"));

        if (easyDma) {
            regs.add(dmaReg("RXD_PTR", base, 0x534L, "RX Buffer Address", NordicEasyDmaType.PTR));
            regs.add(dmaReg("RXD_MAXCNT", base, 0x538L, "Maximum RX Bytes", NordicEasyDmaType.MAXCNT));
            regs.add(dmaReg("RXD_AMOUNT", base, 0x53CL, "Received Bytes", NordicEasyDmaType.AMOUNT));
            regs.add(dmaReg("RXD_LIST", base, 0x540L, "RX List Type", NordicEasyDmaType.LIST));
            regs.add(dmaReg("TXD_PTR", base, 0x544L, "TX Buffer Address", NordicEasyDmaType.PTR));
            regs.add(dmaReg("TXD_MAXCNT", base, 0x548L, "Maximum TX Bytes", NordicEasyDmaType.MAXCNT));
            regs.add(dmaReg("TXD_AMOUNT", base, 0x54CL, "Transmitted Bytes", NordicEasyDmaType.AMOUNT));
            regs.add(dmaReg("TXD_LIST", base, 0x550L, "TX List Type", NordicEasyDmaType.LIST));
        }

        regs.add(reg("ADDRESS", base, 0x588L, "Target I2C Slave Address",
            List.of(new NordicBitField("ADDRESS", 0, 7, 0x7FL, "R/W", "7-bit I2C slave address"))));

        return new NordicPeripheral(name, base, base + 0x1000L, "Two-Wire Interface Master (I2C)", regs);
    }

    public static NordicPeripheral createGpiotePeripheral(long base, String name) {
        List<NordicRegister> regs = new ArrayList<>();
        for (int i = 0; i < 8; i++) {
            regs.add(reg("TASKS_OUT_" + i, base, i * 4L, "Task for output pin " + i));
            regs.add(reg("TASKS_SET_" + i, base, 0x030L + (i * 4L), "Task to set pin " + i));
            regs.add(reg("TASKS_CLR_" + i, base, 0x060L + (i * 4L), "Task to clear pin " + i));
            regs.add(reg("EVENTS_IN_" + i, base, 0x100L + (i * 4L), "Event from pin " + i));
            regs.add(reg("CONFIG_" + i, base, 0x510L + (i * 4L), "Configuration for channel " + i,
                List.of(new NordicBitField("MODE", 0, 2, 0x03L, "R/W", "0=Disabled, 1=Event, 2=Task"),
                        new NordicBitField("PSEL", 8, 5, 0x1F00L, "R/W", "GPIO Pin select"),
                        new NordicBitField("POLARITY", 16, 2, 0x30000L, "R/W",
                            "0=None, 1=LoToHi, 2=HiToLo, 3=Toggle"))));
        }
        regs.add(reg("EVENTS_PORT", base, 0x17CL, "Event from any GPIO port pin"));
        regs.add(reg("INTENSET", base, 0x304L, "Enable interrupt"));
        regs.add(reg("INTENCLR", base, 0x308L, "Disable interrupt"));

        return new NordicPeripheral(name, base, base + 0x1000L, "GPIO Tasks and Events", regs);
    }

    public static NordicPeripheral createTimerPeripheral(long base, String name) {
        List<NordicRegister> regs = new ArrayList<>();
        regs.add(reg("TASKS_START", base, 0x000L, "Start Timer"));
        regs.add(reg("TASKS_STOP", base, 0x004L, "Stop Timer"));
        regs.add(reg("TASKS_COUNT", base, 0x008L, "Increment Timer in Counter mode"));
        regs.add(reg("TASKS_CLEAR", base, 0x00CL, "Clear Timer"));
        for (int i = 0; i < 4; i++) {
            regs.add(reg("EVENTS_COMPARE_" + i, base, 0x140L + (i * 4L), "Compare event on channel " + i));
            regs.add(reg("CC_" + i, base, 0x540L + (i * 4L), "Capture/Compare value " + i));
        }
        regs.add(reg("SHORTS", base, 0x200L, "Shortcuts between local events and tasks"));
        regs.add(reg("INTENSET", base, 0x304L, "Enable interrupt"));
        regs.add(reg("INTENCLR", base, 0x308L, "Disable interrupt"));
        regs.add(reg("MODE", base, 0x504L, "Timer Mode",
            List.of(new NordicBitField("MODE", 0, 2, 0x03L, "R/W", "0=Timer, 1=Counter, 2=LowPowerCounter"))));
        regs.add(reg("BITMODE", base, 0x508L, "Bit Width",
            List.of(new NordicBitField("BITMODE", 0, 2, 0x03L, "R/W", "0=16-bit, 1=8-bit, 2=24-bit, 3=32-bit"))));
        regs.add(reg("PRESCALER", base, 0x510L, "Timer Prescaler",
            List.of(new NordicBitField("PRESCALER", 0, 4, 0x0FL, "R/W", "f_TIMER = 16 MHz / (2^PRESCALER)"))));

        return new NordicPeripheral(name, base, base + 0x1000L, "Timer / Counter Peripheral", regs);
    }

    public static NordicPeripheral createRtcPeripheral(long base, String name) {
        List<NordicRegister> regs = new ArrayList<>();
        regs.add(reg("TASKS_START", base, 0x000L, "Start RTC counter"));
        regs.add(reg("TASKS_STOP", base, 0x004L, "Stop RTC counter"));
        regs.add(reg("TASKS_CLEAR", base, 0x008L, "Clear RTC counter"));
        regs.add(reg("EVENTS_TICK", base, 0x100L, "Event on RTC tick"));
        regs.add(reg("EVENTS_OVRFLW", base, 0x104L, "Event on counter overflow"));
        for (int i = 0; i < 4; i++) {
            regs.add(reg("EVENTS_COMPARE_" + i, base, 0x140L + (i * 4L), "Compare event on channel " + i));
            regs.add(reg("CC_" + i, base, 0x540L + (i * 4L), "Compare register " + i));
        }
        regs.add(reg("INTENSET", base, 0x304L, "Enable interrupt"));
        regs.add(reg("INTENCLR", base, 0x308L, "Disable interrupt"));
        regs.add(reg("COUNTER", base, 0x504L, "Current Counter Value (24-bit)",
            List.of(new NordicBitField("COUNTER", 0, 24, 0x00FFFFFFL, "R", "Current 24-bit counter"))));
        regs.add(reg("PRESCALER", base, 0x508L, "RTC Prescaler",
            List.of(new NordicBitField("PRESCALER", 0, 12, 0x0FFFL, "R/W",
                "RTC frequency = 32768 / (PRESCALER + 1)"))));

        return new NordicPeripheral(name, base, base + 0x1000L, "Real-Time Counter (32.768 kHz)", regs);
    }

    public static NordicPeripheral createTempPeripheral(long base, String name) {
        List<NordicRegister> regs = new ArrayList<>();
        regs.add(reg("TASKS_START", base, 0x000L, "Start temperature measurement"));
        regs.add(reg("TASKS_STOP", base, 0x004L, "Stop temperature measurement"));
        regs.add(reg("EVENTS_DATARDY", base, 0x100L, "Temperature measurement ready"));
        regs.add(reg("INTENSET", base, 0x304L, "Enable interrupt"));
        regs.add(reg("INTENCLR", base, 0x308L, "Disable interrupt"));
        regs.add(reg("TEMP", base, 0x508L, "Temperature Value in Steps of 0.25 deg C"));

        return new NordicPeripheral(name, base, base + 0x1000L, "On-Chip Temperature Sensor", regs);
    }

    public static NordicPeripheral createRngPeripheral(long base, String name) {
        List<NordicRegister> regs = new ArrayList<>();
        regs.add(reg("TASKS_START", base, 0x000L, "Start random number generation"));
        regs.add(reg("TASKS_STOP", base, 0x004L, "Stop random number generation"));
        regs.add(reg("EVENTS_VALRDY", base, 0x100L, "New random value ready"));
        regs.add(reg("SHORTS", base, 0x200L, "Shortcuts between local events and tasks"));
        regs.add(reg("INTENSET", base, 0x304L, "Enable interrupt"));
        regs.add(reg("INTENCLR", base, 0x308L, "Disable interrupt"));
        regs.add(reg("CONFIG", base, 0x504L, "Configuration Register",
            List.of(NordicBitField.singleBit("DERCEN", 0, "R/W", "Digital error correction enable"))));
        regs.add(reg("VALUE", base, 0x508L, "Generated 8-bit Random Value",
            List.of(new NordicBitField("VALUE", 0, 8, 0xFFL, "R", "Random value byte"))));

        return new NordicPeripheral(name, base, base + 0x1000L, "Random Number Generator", regs);
    }

    public static NordicPeripheral createWdtPeripheral(long base, String name) {
        List<NordicRegister> regs = new ArrayList<>();
        regs.add(reg("TASKS_START", base, 0x000L, "Start Watchdog"));
        regs.add(reg("EVENTS_TIMEOUT", base, 0x100L, "Watchdog timeout event"));
        regs.add(reg("INTENSET", base, 0x304L, "Enable interrupt"));
        regs.add(reg("INTENCLR", base, 0x308L, "Disable interrupt"));
        regs.add(reg("RUNSTATUS", base, 0x400L, "Watchdog Run Status",
            List.of(NordicBitField.singleBit("RUNSTATUS", 0, "R", "WDT running flag"))));
        regs.add(reg("CRV", base, 0x504L, "Counter Reload Value"));
        regs.add(reg("RREN", base, 0x508L, "Reload Request Enable"));
        regs.add(reg("CONFIG", base, 0x50CL, "Watchdog Configuration",
            List.of(NordicBitField.singleBit("SLEEP", 0, "R/W", "Keep running while CPU is in sleep"),
                    NordicBitField.singleBit("HALT", 3, "R/W", "Keep running while CPU is halted by debugger"))));
        for (int i = 0; i < 8; i++) {
            regs.add(reg("RR_" + i, base, 0x600L + (i * 4L), "Reload Request Register " + i));
        }

        return new NordicPeripheral(name, base, base + 0x1000L, "Watchdog Timer", regs);
    }

    public static NordicPeripheral createNvmcPeripheral(long base, String name) {
        List<NordicRegister> regs = new ArrayList<>();
        regs.add(reg("READY", base, 0x400L, "Ready Flag",
            List.of(NordicBitField.singleBit("READY", 0, "R", "NVMC ready flag (0=busy, 1=ready)"))));
        regs.add(reg("CONFIG", base, 0x504L, "Configuration Register",
            List.of(new NordicBitField("WEN", 0, 2, 0x03L, "R/W",
                "0=Read-only, 1=Write enable, 2=Erase enable"))));
        regs.add(reg("ERASEPAGE", base, 0x508L, "Erase Page"));
        regs.add(reg("ERASEALL", base, 0x50CL, "Erase All User Flash"));
        regs.add(reg("ERASEUICR", base, 0x514L, "Erase UICR Registers"));
        regs.add(reg("ICACHECNF", base, 0x540L, "Instruction Cache Configuration",
            List.of(NordicBitField.singleBit("CACHEEN", 0, "R/W", "Enable instruction cache"))));

        return new NordicPeripheral(name, base, base + 0x1000L, "Non-Volatile Memory Controller", regs);
    }

    public static NordicPeripheral createSpuPeripheral(long base, String name) {
        List<NordicRegister> regs = new ArrayList<>();
        regs.add(reg("FLASHNSC0_REGION", base, 0x600L, "Flash NSC Region 0 Selection"));
        regs.add(reg("FLASHNSC0_SIZE", base, 0x604L, "Flash NSC Region 0 Size"));
        regs.add(reg("FLASHNSC1_REGION", base, 0x608L, "Flash NSC Region 1 Selection"));
        regs.add(reg("FLASHNSC1_SIZE", base, 0x60CL, "Flash NSC Region 1 Size"));
        for (int i = 0; i < 32; i++) {
            regs.add(reg("FLASHREGION_" + i + "_PERM", base, 0x700L + (i * 4L),
                "Flash Region " + i + " Security Permissions",
                List.of(NordicBitField.singleBit("EXECUTE", 0, "R/W", "Allow instruction execution"),
                        NordicBitField.singleBit("WRITE", 1, "R/W", "Allow write operations"),
                        NordicBitField.singleBit("READ", 2, "R/W", "Allow read operations"),
                        NordicBitField.singleBit("SECATTR", 4, "R/W",
                            "Security attribution: 0=Secure, 1=Non-Secure"))));
            regs.add(reg("RAMREGION_" + i + "_PERM", base, 0x800L + (i * 4L),
                "RAM Region " + i + " Security Permissions",
                List.of(NordicBitField.singleBit("EXECUTE", 0, "R/W", "Allow instruction execution"),
                        NordicBitField.singleBit("WRITE", 1, "R/W", "Allow write operations"),
                        NordicBitField.singleBit("READ", 2, "R/W", "Allow read operations"),
                        NordicBitField.singleBit("SECATTR", 4, "R/W",
                            "Security attribution: 0=Secure, 1=Non-Secure"))));
        }
        for (int i = 0; i < 32; i++) {
            regs.add(reg("PERIPHID_" + i + "_PERM", base, 0x900L + (i * 4L),
                "Peripheral ID " + i + " Security Permissions",
                List.of(NordicBitField.singleBit("SECATTR", 4, "R/W", "0=Secure, 1=Non-Secure"),
                        NordicBitField.singleBit("DMASEC", 5, "R/W", "0=Secure DMA, 1=Non-Secure DMA"))));
        }
        regs.add(reg("CAPABILITIES", base, 0xF00L, "SPU System Protection Unit Capabilities"));

        return new NordicPeripheral(name, base, base + 0x1000L, "ARM TrustZone System Protection Unit (SPU)", regs);
    }

    public static NordicPeripheral createDppiPeripheral(long base, String name) {
        List<NordicRegister> regs = new ArrayList<>();
        regs.add(reg("CHEN", base, 0x500L, "DPPI Channel Enable"));
        regs.add(reg("CHENSET", base, 0x504L, "Set DPPI Channel Enable"));
        regs.add(reg("CHENCLR", base, 0x508L, "Clear DPPI Channel Enable"));
        for (int i = 0; i < 6; i++) {
            regs.add(reg("CHG_" + i, base, 0x800L + (i * 4L), "Channel Group " + i));
        }

        return new NordicPeripheral(name, base, base + 0x1000L,
            "Distributed Programmable Peripheral Interconnect (DPPI)", regs);
    }

    private static NordicRegister reg(String name, long base, long offset, String desc) {
        return new NordicRegister(name, base + offset, offset, 32, desc, List.of());
    }

    private static NordicRegister reg(String name, long base, long offset, String desc, List<NordicBitField> bfs) {
        return new NordicRegister(name, base + offset, offset, 32, desc, bfs);
    }

    private static NordicRegister dmaReg(
            String name, long base, long offset, String desc, NordicEasyDmaType type) {
        return NordicRegister.easyDma(name, base + offset, offset, desc, type);
    }

    public static NordicPeripheralPack forSeries(String series) {
        if (series == null) {
            return createNrf52Pack();
        }
        return switch (series.toUpperCase(java.util.Locale.ROOT)) {
            case "NRF51" -> createNrf51Pack();
            case "NRF53" -> createNrf53Pack();
            case "NRF54" -> createNrf54Pack();
            case "NRF91" -> createNrf91Pack();
            default -> createNrf52Pack();
        };
    }
}
