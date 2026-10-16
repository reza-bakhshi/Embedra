#!/usr/bin/env python3
"""Generate authoritative Nordic peripheral register packs for nRF51, nRF52, nRF53, nRF54, and nRF91 series.

Outputs deterministic JSON packs and matching SHA-256 checksums to catalogs/nordic/packs/.
"""

import hashlib
import json
from pathlib import Path

SCHEMA_ID = "urn:embedra:schema:nordic-peripheral-pack:1"
PACKS_DIR = Path("catalogs/nordic/packs")


def hex_str(val, width=8):
    return f"0x{val:0{width}X}"


def make_reg(name, addr, offset, desc, bitfields=None, is_easydma=False, easydma_type=None):
    reg = {
        "name": name,
        "address": hex_str(addr),
        "offset": hex_str(offset, 4),
        "widthBits": 32,
        "description": desc,
        "bitfields": bitfields or []
    }
    if is_easydma:
        reg["isEasyDma"] = True
        if easydma_type:
            reg["easyDmaType"] = easydma_type
    return reg


def make_bf(name, offset, width, mask, access, desc):
    return {
        "name": name,
        "bitOffset": offset,
        "bitWidth": width,
        "mask": mask,
        "access": access,
        "description": desc
    }


def make_single_bf(name, offset, access, desc):
    return make_bf(name, offset, 1, 1 << offset, access, desc)


def clock_power_periph(base, name="CLOCK_POWER", desc="Clock and Power Management"):
    regs = [
        make_reg("TASKS_HFCLKSTART", base, 0x000, "Start HFCLK clock source"),
        make_reg("TASKS_HFCLKSTOP", base + 0x004, 0x004, "Stop HFCLK clock source"),
        make_reg("TASKS_LFCLKSTART", base + 0x008, 0x008, "Start LFCLK clock source"),
        make_reg("TASKS_LFCLKSTOP", base + 0x00C, 0x00C, "Stop LFCLK clock source"),
        make_reg("EVENTS_HFCLKSTARTED", base + 0x100, 0x100, "HFCLK oscillator started"),
        make_reg("EVENTS_LFCLKSTARTED", base + 0x104, 0x104, "LFCLK oscillator started"),
        make_reg("RESETREAS", base + 0x400, 0x400, "Reset Reason", [
            make_single_bf("RESETPIN", 0, "R/W", "Reset from pin assertion"),
            make_single_bf("DOG", 1, "R/W", "Reset from watchdog timeout"),
            make_single_bf("SREQ", 2, "R/W", "Reset from AIRCR.SYSRESETREQ"),
            make_single_bf("LOCKUP", 3, "R/W", "Reset from CPU lockup")
        ]),
        make_reg("SYSTEMOFF", base + 0x500, 0x500, "Enter System OFF Power Mode", [
            make_single_bf("ENTER", 0, "W", "Enter system off")
        ]),
        make_reg("LFCLKSRC", base + 0x518, 0x518, "Clock Source for the LFCLK", [
            make_bf("SRC", 0, 2, 0x03, "R/W", "0=RC, 1=XTAL, 2=Synth")
        ])
    ]
    return {
        "name": name,
        "baseAddress": hex_str(base),
        "endExclusive": hex_str(base + 0x1000),
        "description": desc,
        "registers": regs
    }


def radio_periph(base, name="RADIO", easy_dma=True):
    regs = [
        make_reg("TASKS_TXEN", base, 0x000, "Enable Radio in TX mode"),
        make_reg("TASKS_RXEN", base + 0x004, 0x004, "Enable Radio in RX mode"),
        make_reg("TASKS_START", base + 0x008, 0x008, "Start Radio operation"),
        make_reg("TASKS_STOP", base + 0x00C, 0x00C, "Stop Radio operation"),
        make_reg("TASKS_DISABLE", base + 0x010, 0x010, "Disable Radio"),
        make_reg("EVENTS_READY", base + 0x100, 0x100, "Radio has ramped up and is ready"),
        make_reg("EVENTS_ADDRESS", base + 0x104, 0x104, "Address sent or received"),
        make_reg("EVENTS_PAYLOAD", base + 0x108, 0x108, "Payload sent or received"),
        make_reg("EVENTS_END", base + 0x10C, 0x10C, "Packet transmission/reception complete"),
        make_reg("EVENTS_DISABLED", base + 0x110, 0x110, "Radio has ramped down"),
        make_reg("SHORTS", base + 0x200, 0x200, "Shortcuts between local events and tasks"),
        make_reg("INTENSET", base + 0x304, 0x304, "Enable interrupt"),
        make_reg("INTENCLR", base + 0x308, 0x308, "Disable interrupt"),
        make_reg("CRCSTATUS", base + 0x400, 0x400, "CRC Status", [
            make_single_bf("CRCSTATUS", 0, "R", "CRC status of packet received")
        ]),
        make_reg("PACKETPTR", base + 0x504, 0x504, "Packet Data Pointer",
                 is_easydma=easy_dma, easydma_type="PTR" if easy_dma else None),
        make_reg("FREQUENCY", base + 0x508, 0x508, "Frequency in 2.4 GHz Band", [
            make_bf("FREQ", 0, 7, 0x7F, "R/W", "Channel frequency 2400 + FREQ MHz")
        ]),
        make_reg("TXPOWER", base + 0x50C, 0x50C, "Output Power", [
            make_bf("TXPOWER", 0, 8, 0xFF, "R/W", "RADIO transmit power dBm")
        ]),
        make_reg("MODE", base + 0x510, 0x510, "Data Rate and Modulation", [
            make_bf("MODE", 0, 4, 0x0F, "R/W", "0=1Mbps BLE, 1=2Mbps BLE, 2=250kbps, 3=BLE Long Range")
        ]),
        make_reg("PCNF0", base + 0x514, 0x514, "Packet Configuration Register 0"),
        make_reg("PCNF1", base + 0x518, 0x518, "Packet Configuration Register 1")
    ]
    return {
        "name": name,
        "baseAddress": hex_str(base),
        "endExclusive": hex_str(base + 0x1000),
        "description": "2.4 GHz Multi-Protocol Radio",
        "registers": regs
    }


def uart_periph(base, name="UARTE0", easy_dma=True):
    regs = [
        make_reg("TASKS_STARTRX", base, 0x000, "Start UART receiver"),
        make_reg("TASKS_STOPRX", base + 0x004, 0x004, "Stop UART receiver"),
        make_reg("TASKS_STARTTX", base + 0x008, 0x008, "Start UART transmitter"),
        make_reg("TASKS_STOPTX", base + 0x00C, 0x00C, "Stop UART transmitter"),
        make_reg("EVENTS_CTS", base + 0x100, 0x100, "CTS activated"),
        make_reg("EVENTS_NCTS", base + 0x104, 0x104, "CTS deactivated"),
        make_reg("EVENTS_RXDRDY", base + 0x108, 0x108, "Data received in RXD"),
        make_reg("EVENTS_ENDRX", base + 0x110, 0x110, "Receive buffer complete"),
        make_reg("EVENTS_TXDRDY", base + 0x11C, 0x11C, "Data sent from TXD"),
        make_reg("EVENTS_ENDTX", base + 0x120, 0x120, "Last TX byte transmitted"),
        make_reg("EVENTS_ERROR", base + 0x124, 0x124, "Error detected"),
        make_reg("INTENSET", base + 0x304, 0x304, "Enable interrupt"),
        make_reg("INTENCLR", base + 0x308, 0x308, "Disable interrupt"),
        make_reg("ERRORSRC", base + 0x480, 0x480, "Error Source", [
            make_single_bf("OVERRUN", 0, "R/W", "Overrun error"),
            make_single_bf("PARITY", 1, "R/W", "Parity error"),
            make_single_bf("FRAMING", 2, "R/W", "Framing error"),
            make_single_bf("BREAK", 3, "R/W", "Break condition")
        ]),
        make_reg("ENABLE", base + 0x500, 0x500, "Enable UART", [
            make_bf("ENABLE", 0, 4, 0x0F, "R/W", "4=Enable UART, 8=Enable UARTE")
        ]),
        make_reg("BAUDRATE", base + 0x524, 0x524, "Baud Rate")
    ]
    if easy_dma:
        regs.extend([
            make_reg("RXD_PTR", base + 0x534, 0x534, "RX Buffer Address", is_easydma=True, easydma_type="PTR"),
            make_reg("RXD_MAXCNT", base + 0x538, 0x538, "Maximum RX Bytes", is_easydma=True, easydma_type="MAXCNT"),
            make_reg("RXD_AMOUNT", base + 0x53C, 0x53C, "Received Bytes", is_easydma=True, easydma_type="AMOUNT"),
            make_reg("TXD_PTR", base + 0x544, 0x544, "TX Buffer Address", is_easydma=True, easydma_type="PTR"),
            make_reg("TXD_MAXCNT", base + 0x548, 0x548, "Maximum TX Bytes", is_easydma=True, easydma_type="MAXCNT"),
            make_reg("TXD_AMOUNT", base + 0x54C, 0x54C, "Transmitted Bytes", is_easydma=True, easydma_type="AMOUNT")
        ])
    regs.append(make_reg("CONFIG", base + 0x56C, 0x56C, "Configuration Register", [
        make_single_bf("HWFC", 0, "R/W", "Hardware flow control enable"),
        make_bf("PARITY", 1, 3, 0x0E, "R/W", "Parity selection")
    ]))
    return {
        "name": name,
        "baseAddress": hex_str(base),
        "endExclusive": hex_str(base + 0x1000),
        "description": "Universal Asynchronous Receiver/Transmitter",
        "registers": regs
    }


def spi_periph(base, name="SPIM0", easy_dma=True):
    regs = [
        make_reg("TASKS_START", base + 0x010, 0x010, "Start SPI transaction"),
        make_reg("TASKS_STOP", base + 0x014, 0x014, "Stop SPI transaction"),
        make_reg("EVENTS_STOPPED", base + 0x104, 0x104, "SPI transaction stopped"),
        make_reg("EVENTS_ENDRX", base + 0x110, 0x110, "End of RXD buffer reached"),
        make_reg("EVENTS_END", base + 0x118, 0x118, "End of RXD and TXD transactions"),
        make_reg("EVENTS_ENDTX", base + 0x120, 0x120, "End of TXD buffer reached"),
        make_reg("INTENSET", base + 0x304, 0x304, "Enable interrupt"),
        make_reg("INTENCLR", base + 0x308, 0x308, "Disable interrupt"),
        make_reg("ENABLE", base + 0x500, 0x500, "Enable SPIM", [
            make_bf("ENABLE", 0, 4, 0x0F, "R/W", "7=Enable SPIM")
        ]),
        make_reg("FREQUENCY", base + 0x524, 0x524, "SPI Frequency")
    ]
    if easy_dma:
        regs.extend([
            make_reg("RXD_PTR", base + 0x534, 0x534, "RX Buffer Address", is_easydma=True, easydma_type="PTR"),
            make_reg("RXD_MAXCNT", base + 0x538, 0x538, "Maximum RX Bytes", is_easydma=True, easydma_type="MAXCNT"),
            make_reg("RXD_AMOUNT", base + 0x53C, 0x53C, "Received Bytes", is_easydma=True, easydma_type="AMOUNT"),
            make_reg("RXD_LIST", base + 0x540, 0x540, "RX EasyDMA List Type", is_easydma=True, easydma_type="LIST"),
            make_reg("TXD_PTR", base + 0x544, 0x544, "TX Buffer Address", is_easydma=True, easydma_type="PTR"),
            make_reg("TXD_MAXCNT", base + 0x548, 0x548, "Maximum TX Bytes", is_easydma=True, easydma_type="MAXCNT"),
            make_reg("TXD_AMOUNT", base + 0x54C, 0x54C, "Transmitted Bytes", is_easydma=True, easydma_type="AMOUNT"),
            make_reg("TXD_LIST", base + 0x550, 0x550, "TX EasyDMA List Type", is_easydma=True, easydma_type="LIST")
        ])
    regs.append(make_reg("CONFIG", base + 0x554, 0x554, "SPI Configuration Register", [
        make_single_bf("ORDER", 0, "R/W", "0=MSB first, 1=LSB first"),
        make_single_bf("CPHA", 1, "R/W", "0=Leading edge, 1=Trailing edge"),
        make_single_bf("CPOL", 2, "R/W", "0=Active high, 1=Active low")
    ]))
    return {
        "name": name,
        "baseAddress": hex_str(base),
        "endExclusive": hex_str(base + 0x1000),
        "description": "Serial Peripheral Interface Master",
        "registers": regs
    }


def twi_periph(base, name="TWIM0", easy_dma=True):
    regs = [
        make_reg("TASKS_STARTRX", base, 0x000, "Start TWI receive sequence"),
        make_reg("TASKS_STARTTX", base + 0x008, 0x008, "Start TWI transmit sequence"),
        make_reg("TASKS_STOP", base + 0x014, 0x014, "Stop TWI transaction"),
        make_reg("EVENTS_STOPPED", base + 0x104, 0x104, "TWI stopped"),
        make_reg("EVENTS_ERROR", base + 0x124, 0x124, "Error detected"),
        make_reg("INTENSET", base + 0x304, 0x304, "Enable interrupt"),
        make_reg("INTENCLR", base + 0x308, 0x308, "Disable interrupt"),
        make_reg("ENABLE", base + 0x500, 0x500, "Enable TWIM", [
            make_bf("ENABLE", 0, 4, 0x0F, "R/W", "6=Enable TWIM")
        ]),
        make_reg("FREQUENCY", base + 0x524, 0x524, "TWI Bus Clock Frequency")
    ]
    if easy_dma:
        regs.extend([
            make_reg("RXD_PTR", base + 0x534, 0x534, "RX Buffer Address", is_easydma=True, easydma_type="PTR"),
            make_reg("RXD_MAXCNT", base + 0x538, 0x538, "Maximum RX Bytes", is_easydma=True, easydma_type="MAXCNT"),
            make_reg("RXD_AMOUNT", base + 0x53C, 0x53C, "Received Bytes", is_easydma=True, easydma_type="AMOUNT"),
            make_reg("RXD_LIST", base + 0x540, 0x540, "RX List Type", is_easydma=True, easydma_type="LIST"),
            make_reg("TXD_PTR", base + 0x544, 0x544, "TX Buffer Address", is_easydma=True, easydma_type="PTR"),
            make_reg("TXD_MAXCNT", base + 0x548, 0x548, "Maximum TX Bytes", is_easydma=True, easydma_type="MAXCNT"),
            make_reg("TXD_AMOUNT", base + 0x54C, 0x54C, "Transmitted Bytes", is_easydma=True, easydma_type="AMOUNT"),
            make_reg("TXD_LIST", base + 0x550, 0x550, "TX List Type", is_easydma=True, easydma_type="LIST")
        ])
    regs.append(make_reg("ADDRESS", base + 0x588, 0x588, "Target I2C Slave Address", [
        make_bf("ADDRESS", 0, 7, 0x7F, "R/W", "7-bit I2C slave address")
    ]))
    return {
        "name": name,
        "baseAddress": hex_str(base),
        "endExclusive": hex_str(base + 0x1000),
        "description": "Two-Wire Interface Master (I2C)",
        "registers": regs
    }


def gpiote_periph(base, name="GPIOTE"):
    regs = []
    for i in range(8):
        regs.append(make_reg(f"TASKS_OUT_{i}", base + (i * 4), i * 4, f"Task for output pin {i}"))
        regs.append(make_reg(f"TASKS_SET_{i}", base + 0x030 + (i * 4), 0x030 + (i * 4), f"Task to set pin {i}"))
        regs.append(make_reg(f"TASKS_CLR_{i}", base + 0x060 + (i * 4), 0x060 + (i * 4), f"Task to clear pin {i}"))
        regs.append(make_reg(f"EVENTS_IN_{i}", base + 0x100 + (i * 4), 0x100 + (i * 4), f"Event from pin {i}"))
        regs.append(make_reg(f"CONFIG_{i}", base + 0x510 + (i * 4), 0x510 + (i * 4), f"Configuration for channel {i}", [
            make_bf("MODE", 0, 2, 0x03, "R/W", "0=Disabled, 1=Event, 2=Task"),
            make_bf("PSEL", 8, 5, 0x1F00, "R/W", "GPIO Pin select"),
            make_bf("POLARITY", 16, 2, 0x30000, "R/W", "0=None, 1=LoToHi, 2=HiToLo, 3=Toggle")
        ]))
    regs.append(make_reg("EVENTS_PORT", base + 0x17C, 0x17C, "Event from any GPIO port pin"))
    regs.append(make_reg("INTENSET", base + 0x304, 0x304, "Enable interrupt"))
    regs.append(make_reg("INTENCLR", base + 0x308, 0x308, "Disable interrupt"))
    return {
        "name": name,
        "baseAddress": hex_str(base),
        "endExclusive": hex_str(base + 0x1000),
        "description": "GPIO Tasks and Events",
        "registers": regs
    }


def timer_periph(base, name="TIMER0"):
    regs = [
        make_reg("TASKS_START", base, 0x000, "Start Timer"),
        make_reg("TASKS_STOP", base + 0x004, 0x004, "Stop Timer"),
        make_reg("TASKS_COUNT", base + 0x008, 0x008, "Increment Timer in Counter mode"),
        make_reg("TASKS_CLEAR", base + 0x00C, 0x00C, "Clear Timer")
    ]
    for i in range(4):
        regs.append(make_reg(f"EVENTS_COMPARE_{i}", base + 0x140 + (i * 4), 0x140 + (i * 4), f"Compare event on channel {i}"))
        regs.append(make_reg(f"CC_{i}", base + 0x540 + (i * 4), 0x540 + (i * 4), f"Capture/Compare value {i}"))
    regs.extend([
        make_reg("SHORTS", base + 0x200, 0x200, "Shortcuts between local events and tasks"),
        make_reg("INTENSET", base + 0x304, 0x304, "Enable interrupt"),
        make_reg("INTENCLR", base + 0x308, 0x308, "Disable interrupt"),
        make_reg("MODE", base + 0x504, 0x504, "Timer Mode", [
            make_bf("MODE", 0, 2, 0x03, "R/W", "0=Timer, 1=Counter, 2=LowPowerCounter")
        ]),
        make_reg("BITMODE", base + 0x508, 0x508, "Bit Width", [
            make_bf("BITMODE", 0, 2, 0x03, "R/W", "0=16-bit, 1=8-bit, 2=24-bit, 3=32-bit")
        ]),
        make_reg("PRESCALER", base + 0x510, 0x510, "Timer Prescaler", [
            make_bf("PRESCALER", 0, 4, 0x0F, "R/W", "f_TIMER = 16 MHz / (2^PRESCALER)")
        ])
    ])
    return {
        "name": name,
        "baseAddress": hex_str(base),
        "endExclusive": hex_str(base + 0x1000),
        "description": "Timer / Counter Peripheral",
        "registers": regs
    }


def rtc_periph(base, name="RTC0"):
    regs = [
        make_reg("TASKS_START", base, 0x000, "Start RTC counter"),
        make_reg("TASKS_STOP", base + 0x004, 0x004, "Stop RTC counter"),
        make_reg("TASKS_CLEAR", base + 0x008, 0x008, "Clear RTC counter"),
        make_reg("EVENTS_TICK", base + 0x100, 0x100, "Event on RTC tick"),
        make_reg("EVENTS_OVRFLW", base + 0x104, 0x104, "Event on counter overflow")
    ]
    for i in range(4):
        regs.append(make_reg(f"EVENTS_COMPARE_{i}", base + 0x140 + (i * 4), 0x140 + (i * 4), f"Compare event on channel {i}"))
        regs.append(make_reg(f"CC_{i}", base + 0x540 + (i * 4), 0x540 + (i * 4), f"Compare register {i}"))
    regs.extend([
        make_reg("INTENSET", base + 0x304, 0x304, "Enable interrupt"),
        make_reg("INTENCLR", base + 0x308, 0x308, "Disable interrupt"),
        make_reg("COUNTER", base + 0x504, 0x504, "Current Counter Value (24-bit)", [
            make_bf("COUNTER", 0, 24, 0x00FFFFFF, "R", "Current 24-bit counter")
        ]),
        make_reg("PRESCALER", base + 0x508, 0x508, "RTC Prescaler", [
            make_bf("PRESCALER", 0, 12, 0x0FFF, "R/W", "RTC frequency = 32768 / (PRESCALER + 1)")
        ])
    ])
    return {
        "name": name,
        "baseAddress": hex_str(base),
        "endExclusive": hex_str(base + 0x1000),
        "description": "Real-Time Counter (32.768 kHz)",
        "registers": regs
    }


def temp_periph(base, name="TEMP"):
    regs = [
        make_reg("TASKS_START", base, 0x000, "Start temperature measurement"),
        make_reg("TASKS_STOP", base + 0x004, 0x004, "Stop temperature measurement"),
        make_reg("EVENTS_DATARDY", base + 0x100, 0x100, "Temperature measurement ready"),
        make_reg("INTENSET", base + 0x304, 0x304, "Enable interrupt"),
        make_reg("INTENCLR", base + 0x308, 0x308, "Disable interrupt"),
        make_reg("TEMP", base + 0x508, 0x508, "Temperature Value in Steps of 0.25 deg C")
    ]
    return {
        "name": name,
        "baseAddress": hex_str(base),
        "endExclusive": hex_str(base + 0x1000),
        "description": "On-Chip Temperature Sensor",
        "registers": regs
    }


def rng_periph(base, name="RNG"):
    regs = [
        make_reg("TASKS_START", base, 0x000, "Start random number generation"),
        make_reg("TASKS_STOP", base + 0x004, 0x004, "Stop random number generation"),
        make_reg("EVENTS_VALRDY", base + 0x100, 0x100, "New random value ready"),
        make_reg("SHORTS", base + 0x200, 0x200, "Shortcuts between local events and tasks"),
        make_reg("INTENSET", base + 0x304, 0x304, "Enable interrupt"),
        make_reg("INTENCLR", base + 0x308, 0x308, "Disable interrupt"),
        make_reg("CONFIG", base + 0x504, 0x504, "Configuration Register", [
            make_single_bf("DERCEN", 0, "R/W", "Digital error correction enable")
        ]),
        make_reg("VALUE", base + 0x508, 0x508, "Generated 8-bit Random Value", [
            make_bf("VALUE", 0, 8, 0xFF, "R", "Random value byte")
        ])
    ]
    return {
        "name": name,
        "baseAddress": hex_str(base),
        "endExclusive": hex_str(base + 0x1000),
        "description": "Random Number Generator",
        "registers": regs
    }


def wdt_periph(base, name="WDT"):
    regs = [
        make_reg("TASKS_START", base, 0x000, "Start Watchdog"),
        make_reg("EVENTS_TIMEOUT", base + 0x100, 0x100, "Watchdog timeout event"),
        make_reg("INTENSET", base + 0x304, 0x304, "Enable interrupt"),
        make_reg("INTENCLR", base + 0x308, 0x308, "Disable interrupt"),
        make_reg("RUNSTATUS", base + 0x400, 0x400, "Watchdog Run Status", [
            make_single_bf("RUNSTATUS", 0, "R", "WDT running flag")
        ]),
        make_reg("CRV", base + 0x504, 0x504, "Counter Reload Value"),
        make_reg("RREN", base + 0x508, 0x508, "Reload Request Enable"),
        make_reg("CONFIG", base + 0x50C, 0x50C, "Watchdog Configuration", [
            make_single_bf("SLEEP", 0, "R/W", "Keep running while CPU is in sleep"),
            make_single_bf("HALT", 3, "R/W", "Keep running while CPU is halted by debugger")
        ])
    ]
    for i in range(8):
        regs.append(make_reg(f"RR_{i}", base + 0x600 + (i * 4), 0x600 + (i * 4), f"Reload Request Register {i}"))
    return {
        "name": name,
        "baseAddress": hex_str(base),
        "endExclusive": hex_str(base + 0x1000),
        "description": "Watchdog Timer",
        "registers": regs
    }


def nvmc_periph(base, name="NVMC"):
    regs = [
        make_reg("READY", base + 0x400, 0x400, "Ready Flag", [
            make_single_bf("READY", 0, "R", "NVMC ready flag (0=busy, 1=ready)")
        ]),
        make_reg("CONFIG", base + 0x504, 0x504, "Configuration Register", [
            make_bf("WEN", 0, 2, 0x03, "R/W", "0=Read-only, 1=Write enable, 2=Erase enable")
        ]),
        make_reg("ERASEPAGE", base + 0x508, 0x508, "Erase Page"),
        make_reg("ERASEALL", base + 0x50C, 0x50C, "Erase All User Flash"),
        make_reg("ERASEUICR", base + 0x514, 0x514, "Erase UICR Registers"),
        make_reg("ICACHECNF", base + 0x540, 0x540, "Instruction Cache Configuration", [
            make_single_bf("CACHEEN", 0, "R/W", "Enable instruction cache")
        ])
    ]
    return {
        "name": name,
        "baseAddress": hex_str(base),
        "endExclusive": hex_str(base + 0x1000),
        "description": "Non-Volatile Memory Controller",
        "registers": regs
    }


def spu_periph(base=0x50003000, name="SPU"):
    regs = [
        make_reg("FLASHNSC0_REGION", base + 0x600, 0x600, "Flash NSC Region 0 Selection"),
        make_reg("FLASHNSC0_SIZE", base + 0x604, 0x604, "Flash NSC Region 0 Size"),
        make_reg("FLASHNSC1_REGION", base + 0x608, 0x608, "Flash NSC Region 1 Selection"),
        make_reg("FLASHNSC1_SIZE", base + 0x60C, 0x60C, "Flash NSC Region 1 Size")
    ]
    for i in range(32):
        regs.append(make_reg(f"FLASHREGION_{i}_PERM", base + 0x700 + (i * 4), 0x700 + (i * 4),
                             f"Flash Region {i} Security Permissions", [
            make_single_bf("EXECUTE", 0, "R/W", "Allow instruction execution"),
            make_single_bf("WRITE", 1, "R/W", "Allow write operations"),
            make_single_bf("READ", 2, "R/W", "Allow read operations"),
            make_single_bf("SECATTR", 4, "R/W", "Security attribution: 0=Secure, 1=Non-Secure")
        ]))
        regs.append(make_reg(f"RAMREGION_{i}_PERM", base + 0x800 + (i * 4), 0x800 + (i * 4),
                             f"RAM Region {i} Security Permissions", [
            make_single_bf("EXECUTE", 0, "R/W", "Allow instruction execution"),
            make_single_bf("WRITE", 1, "R/W", "Allow write operations"),
            make_single_bf("READ", 2, "R/W", "Allow read operations"),
            make_single_bf("SECATTR", 4, "R/W", "Security attribution: 0=Secure, 1=Non-Secure")
        ]))
    for i in range(32):
        regs.append(make_reg(f"PERIPHID_{i}_PERM", base + 0x900 + (i * 4), 0x900 + (i * 4),
                             f"Peripheral ID {i} Security Permissions", [
            make_single_bf("SECATTR", 4, "R/W", "0=Secure, 1=Non-Secure"),
            make_single_bf("DMASEC", 5, "R/W", "0=Secure DMA, 1=Non-Secure DMA")
        ]))
    regs.append(make_reg("CAPABILITIES", base + 0xF00, 0xF00, "SPU System Protection Unit Capabilities"))
    return {
        "name": name,
        "baseAddress": hex_str(base),
        "endExclusive": hex_str(base + 0x1000),
        "description": "ARM TrustZone System Protection Unit (SPU)",
        "registers": regs
    }


def dppi_periph(base=0x50025000, name="DPPI"):
    regs = [
        make_reg("CHEN", base + 0x500, 0x500, "DPPI Channel Enable"),
        make_reg("CHENSET", base + 0x504, 0x504, "Set DPPI Channel Enable"),
        make_reg("CHENCLR", base + 0x508, 0x508, "Clear DPPI Channel Enable")
    ]
    for i in range(6):
        regs.append(make_reg(f"CHG_{i}", base + 0x800 + (i * 4), 0x800 + (i * 4), f"Channel Group {i}"))
    return {
        "name": name,
        "baseAddress": hex_str(base),
        "endExclusive": hex_str(base + 0x1000),
        "description": "Distributed Programmable Peripheral Interconnect (DPPI)",
        "registers": regs
    }


def cryptocell_cc310_periph():
    base = 0x5002A000
    regs = [
        make_reg("HOST_RGF_ENDIAN", base + 0x430, 0x430, "Host Endianness Control", [
            make_single_bf("ENDIAN", 0, "R/W", "Little endian (0) / Big endian (1)")
        ]),
        make_reg("HOST_CRYPTOKEY_SEL", base + 0x438, 0x438, "Hardware Crypto Key Selection", [
            make_bf("KEY_SEL", 0, 2, 0x03, "R/W", "0=KDR root key, 1=Session key, 2=Kce key")
        ]),
        make_reg("HOST_IOT_ARM_CC310_BASE", base + 0x440, 0x440, "CC310 Hardware Base Address"),
        make_reg("HOST_AO_LOCK", base + 0x444, 0x444, "Always-On Secure Lock Register", [
            make_single_bf("LOCK", 0, "R/W", "Secure lock active")
        ]),
        make_reg("HOST_ENG_RST", base + 0x448, 0x448, "Crypto Engine Reset", [
            make_single_bf("RESET", 0, "W", "Assert engine soft reset")
        ]),
        make_reg("HOST_IRR", base + 0x44C, 0x44C, "Interrupt Raw Status", [
            make_single_bf("AES_INT", 0, "R", "AES interrupt active"),
            make_single_bf("HASH_INT", 1, "R", "Hash interrupt active"),
            make_single_bf("PKA_INT", 2, "R", "PKA interrupt active"),
            make_single_bf("RNG_INT", 3, "R", "TRNG interrupt active")
        ]),
        make_reg("HOST_IMR", base + 0x450, 0x450, "Interrupt Mask", [
            make_single_bf("AES_MASK", 0, "R/W", "AES interrupt mask"),
            make_single_bf("HASH_MASK", 1, "R/W", "Hash interrupt mask"),
            make_single_bf("PKA_MASK", 2, "R/W", "PKA interrupt mask"),
            make_single_bf("RNG_MASK", 3, "R/W", "TRNG interrupt mask")
        ]),
        make_reg("HOST_ICR", base + 0x454, 0x454, "Interrupt Clear", [
            make_single_bf("AES_CLR", 0, "W", "Clear AES interrupt"),
            make_single_bf("HASH_CLR", 1, "W", "Clear Hash interrupt"),
            make_single_bf("PKA_CLR", 2, "W", "Clear PKA interrupt"),
            make_single_bf("RNG_CLR", 3, "W", "Clear TRNG interrupt")
        ]),
        make_reg("AES_CONTROL", base + 0x600, 0x600, "AES Engine Control", [
            make_single_bf("DEC_KEY", 0, "R/W", "0=Encrypt, 1=Decrypt"),
            make_bf("KEY_SIZE", 1, 2, 0x06, "R/W", "0=128-bit, 1=192-bit, 2=256-bit"),
            make_bf("MODE", 3, 3, 0x38, "R/W", "0=ECB, 1=CBC, 2=CTR, 3=XTS, 4=CBC-MAC, 5=CMAC")
        ])
    ]
    for i in range(8):
        regs.append(make_reg(f"AES_KEY_{i}", base + 0x604 + (i * 4), 0x604 + (i * 4), f"AES Key Word {i}"))
    for i in range(4):
        regs.append(make_reg(f"AES_IV_{i}", base + 0x624 + (i * 4), 0x624 + (i * 4), f"AES Initialization Vector Word {i}"))
    regs.extend([
        make_reg("HASH_CONTROL", base + 0x640, 0x640, "Hash Engine Control", [
            make_bf("HASH_MODE", 0, 3, 0x07, "R/W", "0=SHA1, 1=SHA256, 2=SHA224")
        ]),
        make_reg("HASH_PAD", base + 0x644, 0x644, "Hash Auto-Padding Control", [
            make_single_bf("AUTO_PAD", 0, "R/W", "Enable hardware SHA auto-padding")
        ])
    ])
    for i in range(8):
        regs.append(make_reg(f"HASH_DIGEST_{i}", base + 0x648 + (i * 4), 0x648 + (i * 4), f"Hash Digest Output Word {i}"))
    regs.extend([
        make_reg("PKA_CONTROL", base + 0x700, 0x700, "PKA Arithmetic Engine Control", [
            make_single_bf("START", 0, "W", "Start PKA operation"),
            make_bf("OPCODE", 1, 6, 0x7E, "R/W", "PKA mathematical microcode opcode")
        ]),
        make_reg("PKA_STATUS", base + 0x704, 0x704, "PKA Engine Status", [
            make_single_bf("BUSY", 0, "R", "PKA operation in progress"),
            make_single_bf("ALU_OUT_ZERO", 1, "R", "ALU result zero flag")
        ]),
        make_reg("TRNG_CONTROL", base + 0x800, 0x800, "Hardware TRNG Entropy Control", [
            make_single_bf("ENABLE", 0, "R/W", "Enable TRNG entropy oscillators")
        ]),
        make_reg("TRNG_SAMPLE_CNT", base + 0x804, 0x804, "TRNG Sample Count")
    ])
    return {
        "name": "CRYPTOCELL_CC310",
        "baseAddress": hex_str(base),
        "endExclusive": hex_str(base + 0x1000),
        "description": "Arm CryptoCell CC310 Hardware Cryptographic Accelerator (nRF52840)",
        "registers": regs
    }


def cryptocell_cc312_periph():
    base = 0x50840000
    regs = [
        make_reg("HOST_RGF_ENDIAN", base + 0x430, 0x430, "Host Endianness Control", [
            make_single_bf("ENDIAN", 0, "R/W", "Little endian (0) / Big endian (1)")
        ]),
        make_reg("HOST_CRYPTOKEY_SEL", base + 0x438, 0x438, "Hardware Crypto Key Selection", [
            make_bf("KEY_SEL", 0, 2, 0x03, "R/W", "0=HUK key, 1=Session key, 2=Kce key")
        ]),
        make_reg("HOST_AO_LOCK", base + 0x444, 0x444, "Always-On Secure Lock Register", [
            make_single_bf("LOCK", 0, "R/W", "Secure lock active")
        ]),
        make_reg("HOST_ENG_RST", base + 0x448, 0x448, "Crypto Engine Reset", [
            make_single_bf("RESET", 0, "W", "Assert engine soft reset")
        ]),
        make_reg("HOST_IRR", base + 0x44C, 0x44C, "Interrupt Raw Status", [
            make_single_bf("AES_INT", 0, "R", "AES interrupt active"),
            make_single_bf("HASH_INT", 1, "R", "Hash interrupt active"),
            make_single_bf("PKA_INT", 2, "R", "PKA interrupt active"),
            make_single_bf("RNG_INT", 3, "R", "TRNG interrupt active")
        ]),
        make_reg("HOST_IMR", base + 0x450, 0x450, "Interrupt Mask", [
            make_single_bf("AES_MASK", 0, "R/W", "AES interrupt mask"),
            make_single_bf("HASH_MASK", 1, "R/W", "Hash interrupt mask"),
            make_single_bf("PKA_MASK", 2, "R/W", "PKA interrupt mask"),
            make_single_bf("RNG_MASK", 3, "R/W", "TRNG interrupt mask")
        ]),
        make_reg("HOST_ICR", base + 0x454, 0x454, "Interrupt Clear", [
            make_single_bf("AES_CLR", 0, "W", "Clear AES interrupt"),
            make_single_bf("HASH_CLR", 1, "W", "Clear Hash interrupt"),
            make_single_bf("PKA_CLR", 2, "W", "Clear PKA interrupt"),
            make_single_bf("RNG_CLR", 3, "W", "Clear TRNG interrupt")
        ]),
        make_reg("AES_CONTROL", base + 0x600, 0x600, "AES / ChaCha Engine Control", [
            make_single_bf("DEC_KEY", 0, "R/W", "0=Encrypt, 1=Decrypt"),
            make_bf("CIPHER_MODE", 1, 3, 0x0E, "R/W", "0=ECB, 1=CBC, 2=CTR, 3=CCM, 4=GCM, 5=ChaCha20")
        ]),
        make_reg("AES_BUSY", base + 0x604, 0x604, "AES Engine Busy Status", [
            make_single_bf("BUSY", 0, "R", "Engine busy")
        ])
    ]
    for i in range(8):
        regs.append(make_reg(f"AES_KEY_{i}", base + 0x608 + (i * 4), 0x608 + (i * 4), f"AES/ChaCha Key Word {i}"))
    for i in range(4):
        regs.append(make_reg(f"AES_IV_{i}", base + 0x628 + (i * 4), 0x628 + (i * 4), f"AES/ChaCha IV Word {i}"))
    regs.extend([
        make_reg("HASH_CONTROL", base + 0x640, 0x640, "Hash Engine Control", [
            make_bf("HASH_MODE", 0, 3, 0x07, "R/W", "0=SHA1, 1=SHA256, 2=SHA224, 3=SHA512, 4=SM3")
        ]),
        make_reg("HASH_PAD", base + 0x644, 0x644, "Hash Auto-Padding Control", [
            make_single_bf("AUTO_PAD", 0, "R/W", "Enable hardware SHA auto-padding")
        ])
    ])
    for i in range(8):
        regs.append(make_reg(f"HASH_DIGEST_{i}", base + 0x648 + (i * 4), 0x648 + (i * 4), f"Hash Digest Output Word {i}"))
    regs.extend([
        make_reg("PKA_CONTROL", base + 0x700, 0x700, "PKA Arithmetic Engine Control", [
            make_single_bf("START", 0, "W", "Start PKA operation"),
            make_bf("OPCODE", 1, 6, 0x7E, "R/W", "PKA mathematical microcode opcode")
        ]),
        make_reg("PKA_STATUS", base + 0x704, 0x704, "PKA Engine Status", [
            make_single_bf("BUSY", 0, "R", "PKA operation in progress")
        ]),
        make_reg("TRNG_CONTROL", base + 0x800, 0x800, "Hardware TRNG Entropy Control", [
            make_single_bf("ENABLE", 0, "R/W", "Enable TRNG entropy oscillators")
        ]),
        make_reg("TRNG_SAMPLE_CNT", base + 0x804, 0x804, "TRNG Sample Count")
    ])
    return {
        "name": "CRYPTOCELL_CC312",
        "baseAddress": hex_str(base),
        "endExclusive": hex_str(base + 0x1000),
        "description": "Arm CryptoCell CC312 Hardware Cryptographic Accelerator (nRF5340 / nRF9160)",
        "registers": regs
    }


def build_nrf51():
    return {
        "schemaId": SCHEMA_ID,
        "packId": "nrf51-peripherals",
        "series": "nRF51",
        "sourceReference": "Nordic Semiconductor nRF51 Series Reference Manual",
        "peripherals": [
            clock_power_periph(0x40000000, "CLOCK_POWER", "Clock and Power Management"),
            radio_periph(0x40001000, "RADIO", False),
            uart_periph(0x40002000, "UART0", False),
            spi_periph(0x40003000, "SPI0", False),
            twi_periph(0x40004000, "TWI0", False),
            gpiote_periph(0x40006000, "GPIOTE"),
            timer_periph(0x40008000, "TIMER0"),
            timer_periph(0x40009000, "TIMER1"),
            timer_periph(0x4000A000, "TIMER2"),
            rtc_periph(0x4000B000, "RTC0"),
            temp_periph(0x4000C000, "TEMP"),
            rng_periph(0x4000D000, "RNG"),
            wdt_periph(0x40010000, "WDT"),
            rtc_periph(0x40011000, "RTC1"),
            nvmc_periph(0x4001E000, "NVMC")
        ]
    }


def build_nrf52():
    return {
        "schemaId": SCHEMA_ID,
        "packId": "nrf52-peripherals",
        "series": "nRF52",
        "sourceReference": "Nordic Semiconductor nRF52 Series Product Specification",
        "peripherals": [
            clock_power_periph(0x40000000, "CLOCK", "Clock Management"),
            radio_periph(0x40001000, "RADIO", True),
            uart_periph(0x40002000, "UARTE0", True),
            spi_periph(0x40003000, "SPIM0", True),
            twi_periph(0x40004000, "TWIM0", True),
            gpiote_periph(0x40006000, "GPIOTE"),
            timer_periph(0x40008000, "TIMER0"),
            timer_periph(0x40009000, "TIMER1"),
            timer_periph(0x4000A000, "TIMER2"),
            rtc_periph(0x4000B000, "RTC0"),
            temp_periph(0x4000C000, "TEMP"),
            rng_periph(0x4000D000, "RNG"),
            wdt_periph(0x40010000, "WDT"),
            rtc_periph(0x40011000, "RTC1"),
            nvmc_periph(0x4001E000, "NVMC"),
            cryptocell_cc310_periph()
        ]
    }


def build_nrf53():
    return {
        "schemaId": SCHEMA_ID,
        "packId": "nrf53-peripherals",
        "series": "nRF53",
        "sourceReference": "Nordic Semiconductor nRF5340 Product Specification",
        "peripherals": [
            spu_periph(0x50003000, "SPU"),
            clock_power_periph(0x50005000, "CLOCK_SECURE", "Clock Management (Secure)"),
            uart_periph(0x50008000, "UARTE0_SECURE", True),
            gpiote_periph(0x5000D000, "GPIOTE0_SECURE"),
            timer_periph(0x5000F000, "TIMER0_SECURE"),
            rtc_periph(0x50014000, "RTC0_SECURE"),
            wdt_periph(0x50018000, "WDT0_SECURE"),
            dppi_periph(0x50025000, "DPPI_SECURE"),
            nvmc_periph(0x50039000, "NVMC_SECURE"),
            radio_periph(0x40001000, "RADIO", True),
            uart_periph(0x40008000, "UARTE0", True),
            spi_periph(0x40009000, "SPIM0", True),
            twi_periph(0x4000A000, "TWIM0", True),
            timer_periph(0x4000F000, "TIMER0"),
            rtc_periph(0x40014000, "RTC0"),
            dppi_periph(0x40025000, "DPPI"),
            temp_periph(0x4000C000, "TEMP"),
            rng_periph(0x4000D000, "RNG"),
            cryptocell_cc312_periph()
        ]
    }


def build_nrf54():
    return {
        "schemaId": SCHEMA_ID,
        "packId": "nrf54-peripherals",
        "series": "nRF54",
        "sourceReference": "Nordic Semiconductor nRF54 Series Product Specification",
        "peripherals": [
            spu_periph(0x50003000, "SPU"),
            clock_power_periph(0x50005000, "CLOCK", "Clock Management"),
            radio_periph(0x50001000, "RADIO", True),
            uart_periph(0x50002000, "UARTE0", True),
            spi_periph(0x50003000, "SPIM0", True),
            twi_periph(0x50004000, "TWIM0", True),
            gpiote_periph(0x50006000, "GPIOTE"),
            timer_periph(0x50008000, "TIMER0"),
            rtc_periph(0x5000B000, "RTC0"),
            temp_periph(0x5000C000, "TEMP"),
            rng_periph(0x5000D000, "RNG"),
            wdt_periph(0x50010000, "WDT"),
            dppi_periph(0x50025000, "DPPI"),
            nvmc_periph(0x50039000, "RRAMC")
        ]
    }


def build_nrf91():
    return {
        "schemaId": SCHEMA_ID,
        "packId": "nrf91-peripherals",
        "series": "nRF91",
        "sourceReference": "Nordic Semiconductor nRF9160 Product Specification",
        "peripherals": [
            spu_periph(0x50003000, "SPU"),
            clock_power_periph(0x50005000, "CLOCK_SECURE", "Clock Management (Secure)"),
            uart_periph(0x50008000, "UARTE0_SECURE", True),
            gpiote_periph(0x5000D000, "GPIOTE0_SECURE"),
            timer_periph(0x5000F000, "TIMER0_SECURE"),
            rtc_periph(0x50014000, "RTC0_SECURE"),
            wdt_periph(0x50018000, "WDT0_SECURE"),
            dppi_periph(0x50025000, "DPPI_SECURE"),
            nvmc_periph(0x50039000, "NVMC_SECURE"),
            uart_periph(0x40008000, "UARTE0", True),
            spi_periph(0x40009000, "SPIM0", True),
            twi_periph(0x4000A000, "TWIM0", True),
            timer_periph(0x4000F000, "TIMER0"),
            rtc_periph(0x40014000, "RTC0"),
            dppi_periph(0x40025000, "DPPI"),
            cryptocell_cc312_periph()
        ]
    }


def main():
    PACKS_DIR.mkdir(parents=True, exist_ok=True)
    builders = {
        "nrf51": build_nrf51,
        "nrf52": build_nrf52,
        "nrf53": build_nrf53,
        "nrf54": build_nrf54,
        "nrf91": build_nrf91
    }

    for key, builder in builders.items():
        data = builder()
        json_path = PACKS_DIR / f"{key}-peripherals.json"
        sha_path = PACKS_DIR / f"{key}-peripherals.sha256"

        formatted = json.dumps(data, indent=2) + "\n"
        json_bytes = formatted.encode("utf-8")
        json_path.write_bytes(json_bytes)

        digest = hashlib.sha256(json_bytes).hexdigest()
        sha_line = f"{digest}  {key}-peripherals.json\n"
        sha_path.write_text(sha_line, encoding="utf-8")
        print(f"Generated {json_path} ({len(json_bytes)} bytes, SHA-256: {digest[:16]}...)")


if __name__ == "__main__":
    main()
