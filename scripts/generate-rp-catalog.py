#!/usr/bin/env python3
"""Deterministic generator for authoritative Raspberry Pi silicon and board catalogs.

Covers RP2040, RP2350A/B, RP2354A/B, and official Pico/Pico W/Pico 2/Pico 2 W board profiles.
All records start in the explicit PLANNED state per Embedra specification (RP-002, STM-019).
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT_DIR = ROOT / "catalogs" / "rp" / "2026-10-02"

RP_CATALOG_SCHEMA = "urn:embedra:schema:rp-catalog:1"
RP_BOARD_PROFILES_SCHEMA = "urn:embedra:schema:rp-board-profiles:1"

# Authoritative silicon specifications derived from official Raspberry Pi datasheets
# - RP2040 Datasheet (Build 2024-08, release 8)
# - RP2350 Datasheet (Build 2024-08, release 1)
SILICON_RECORDS = [
    {
        "recordId": "rp:silicon:rp2040",
        "exactPart": "RP2040",
        "series": "RP2040",
        "vendor": "Raspberry Pi Ltd",
        "package": "QFN-56",
        "dimensions": "7x7mm",
        "gpioCount": 30,
        "internalFlashBytes": 0,
        "externalXipLimitBytes": 16 * 1024 * 1024,
        "sramBytes": 264 * 1024,
        "sramBanks": [
            {"name": "SRAM0", "baseAddress": 0x20000000, "sizeBytes": 64 * 1024, "striped": True},
            {"name": "SRAM1", "baseAddress": 0x20010000, "sizeBytes": 64 * 1024, "striped": True},
            {"name": "SRAM2", "baseAddress": 0x20020000, "sizeBytes": 64 * 1024, "striped": True},
            {"name": "SRAM3", "baseAddress": 0x20030000, "sizeBytes": 64 * 1024, "striped": True},
            {"name": "SRAM4", "baseAddress": 0x20040000, "sizeBytes": 4 * 1024, "striped": False},
            {"name": "SRAM5", "baseAddress": 0x20041000, "sizeBytes": 4 * 1024, "striped": False}
        ],
        "bootRomBytes": 16 * 1024,
        "bootRomBase": 0x00000000,
        "flashXipBase": 0x10000000,
        "applicationCoreCount": 2,
        "bootArchitectures": ["ARM_CORTEX_M0P"],
        "architectureSelectionMode": "FIXED_SINGLE_ISA",
        "pioBlocks": 2,
        "pioStateMachinesPerBlock": 4,
        "hasAtomicAliases": True,
        "atomicAliasBase": 0x50000000,
        "sioBase": 0xD0000000,
        "securityCapabilities": [],
        "peripheralNames": [
            "ADC", "BUSCTRL", "CLOCKS", "DMA", "I2C0", "I2C1", "IO_BANK0", "IO_QSPI",
            "PADS_BANK0", "PADS_QSPI", "PIO0", "PIO1", "PLL_SYS", "PLL_USB", "PSM",
            "PWM", "RESETS", "ROSC", "RTC", "SIO", "SPI0", "SPI1", "SYSCONFIG",
            "SYSINFO", "TBMAN", "TIMER", "UART0", "UART1", "USB", "VREG_AND_CHIP_RESET",
            "WATCHDOG", "XIP_AUX", "XIP_CTRL", "XIP_SSI", "XOSC"
        ],
        "supportState": "PLANNED",
        "sourceProvenance": {
            "title": "RP2040 Datasheet: A microcontroller by Raspberry Pi",
            "revision": "release 8 (2024-08)",
            "url": "https://datasheets.raspberrypi.com/rp2040/rp2040-datasheet.pdf",
            "license": "CC-BY-ND-4.0 / Hardware Documentation License"
        }
    },
    {
        "recordId": "rp:silicon:rp2350a",
        "exactPart": "RP2350A",
        "series": "RP2350",
        "vendor": "Raspberry Pi Ltd",
        "package": "QFN-60",
        "dimensions": "7x7mm",
        "gpioCount": 30,
        "internalFlashBytes": 0,
        "externalXipLimitBytes": 16 * 1024 * 1024,
        "sramBytes": 520 * 1024,
        "sramBanks": [
            {"name": "SRAM0", "baseAddress": 0x20000000, "sizeBytes": 64 * 1024, "striped": True},
            {"name": "SRAM1", "baseAddress": 0x20010000, "sizeBytes": 64 * 1024, "striped": True},
            {"name": "SRAM2", "baseAddress": 0x20020000, "sizeBytes": 64 * 1024, "striped": True},
            {"name": "SRAM3", "baseAddress": 0x20030000, "sizeBytes": 64 * 1024, "striped": True},
            {"name": "SRAM4", "baseAddress": 0x20040000, "sizeBytes": 64 * 1024, "striped": True},
            {"name": "SRAM5", "baseAddress": 0x20050000, "sizeBytes": 64 * 1024, "striped": True},
            {"name": "SRAM6", "baseAddress": 0x20060000, "sizeBytes": 64 * 1024, "striped": True},
            {"name": "SRAM7", "baseAddress": 0x20070000, "sizeBytes": 64 * 1024, "striped": True},
            {"name": "SRAM8", "baseAddress": 0x20080000, "sizeBytes": 4 * 1024, "striped": False},
            {"name": "SRAM9", "baseAddress": 0x20081000, "sizeBytes": 4 * 1024, "striped": False}
        ],
        "bootRomBytes": 32 * 1024,
        "bootRomBase": 0x00000000,
        "flashXipBase": 0x10000000,
        "applicationCoreCount": 2,
        "bootArchitectures": ["ARM_CORTEX_M33", "HAZARD3_RISCV"],
        "architectureSelectionMode": "IMAGE_DEF_SELECTABLE_AT_BOOT",
        "pioBlocks": 3,
        "pioStateMachinesPerBlock": 4,
        "hasAtomicAliases": True,
        "atomicAliasBase": 0x50000000,
        "sioBase": 0xD0000000,
        "securityCapabilities": ["ARM_TRUSTZONE", "OTP_8KB", "HARDWARE_SHA256", "TRNG", "SECURE_BOOT"],
        "peripheralNames": [
            "ADC", "BUSCTRL", "CLOCKS", "DMA", "HSTX", "I2C0", "I2C1", "IO_BANK0", "IO_QSPI",
            "OTP", "PADS_BANK0", "PADS_QSPI", "PIO0", "PIO1", "PIO2", "PLL_SYS", "PLL_USB",
            "POWMAN", "PWM", "QMI", "RESETS", "ROSC", "RTC", "SHA256", "SIO", "SPI0", "SPI1",
            "SYSCONFIG", "SYSINFO", "TBMAN", "TICKS", "TIMER0", "TIMER1", "TRNG", "UART0",
            "UART1", "USB", "VREG_AND_CHIP_RESET", "WATCHDOG", "XIP_AUX", "XIP_CTRL", "XOSC"
        ],
        "supportState": "PLANNED",
        "sourceProvenance": {
            "title": "RP2350 Datasheet: A microcontroller by Raspberry Pi",
            "revision": "release 1 (2024-08)",
            "url": "https://datasheets.raspberrypi.com/rp2350/rp2350-datasheet.pdf",
            "license": "CC-BY-ND-4.0 / Hardware Documentation License"
        }
    },
    {
        "recordId": "rp:silicon:rp2350b",
        "exactPart": "RP2350B",
        "series": "RP2350",
        "vendor": "Raspberry Pi Ltd",
        "package": "QFN-80",
        "dimensions": "10x10mm",
        "gpioCount": 48,
        "internalFlashBytes": 0,
        "externalXipLimitBytes": 16 * 1024 * 1024,
        "sramBytes": 520 * 1024,
        "sramBanks": [
            {"name": "SRAM0", "baseAddress": 0x20000000, "sizeBytes": 64 * 1024, "striped": True},
            {"name": "SRAM1", "baseAddress": 0x20010000, "sizeBytes": 64 * 1024, "striped": True},
            {"name": "SRAM2", "baseAddress": 0x20020000, "sizeBytes": 64 * 1024, "striped": True},
            {"name": "SRAM3", "baseAddress": 0x20030000, "sizeBytes": 64 * 1024, "striped": True},
            {"name": "SRAM4", "baseAddress": 0x20040000, "sizeBytes": 64 * 1024, "striped": True},
            {"name": "SRAM5", "baseAddress": 0x20050000, "sizeBytes": 64 * 1024, "striped": True},
            {"name": "SRAM6", "baseAddress": 0x20060000, "sizeBytes": 64 * 1024, "striped": True},
            {"name": "SRAM7", "baseAddress": 0x20070000, "sizeBytes": 64 * 1024, "striped": True},
            {"name": "SRAM8", "baseAddress": 0x20080000, "sizeBytes": 4 * 1024, "striped": False},
            {"name": "SRAM9", "baseAddress": 0x20081000, "sizeBytes": 4 * 1024, "striped": False}
        ],
        "bootRomBytes": 32 * 1024,
        "bootRomBase": 0x00000000,
        "flashXipBase": 0x10000000,
        "applicationCoreCount": 2,
        "bootArchitectures": ["ARM_CORTEX_M33", "HAZARD3_RISCV"],
        "architectureSelectionMode": "IMAGE_DEF_SELECTABLE_AT_BOOT",
        "pioBlocks": 3,
        "pioStateMachinesPerBlock": 4,
        "hasAtomicAliases": True,
        "atomicAliasBase": 0x50000000,
        "sioBase": 0xD0000000,
        "securityCapabilities": ["ARM_TRUSTZONE", "OTP_8KB", "HARDWARE_SHA256", "TRNG", "SECURE_BOOT"],
        "peripheralNames": [
            "ADC", "BUSCTRL", "CLOCKS", "DMA", "HSTX", "I2C0", "I2C1", "IO_BANK0", "IO_QSPI",
            "OTP", "PADS_BANK0", "PADS_QSPI", "PIO0", "PIO1", "PIO2", "PLL_SYS", "PLL_USB",
            "POWMAN", "PWM", "QMI", "RESETS", "ROSC", "RTC", "SHA256", "SIO", "SPI0", "SPI1",
            "SYSCONFIG", "SYSINFO", "TBMAN", "TICKS", "TIMER0", "TIMER1", "TRNG", "UART0",
            "UART1", "USB", "VREG_AND_CHIP_RESET", "WATCHDOG", "XIP_AUX", "XIP_CTRL", "XOSC"
        ],
        "supportState": "PLANNED",
        "sourceProvenance": {
            "title": "RP2350 Datasheet: A microcontroller by Raspberry Pi",
            "revision": "release 1 (2024-08)",
            "url": "https://datasheets.raspberrypi.com/rp2350/rp2350-datasheet.pdf",
            "license": "CC-BY-ND-4.0 / Hardware Documentation License"
        }
    },
    {
        "recordId": "rp:silicon:rp2354a",
        "exactPart": "RP2354A",
        "series": "RP2354",
        "vendor": "Raspberry Pi Ltd",
        "package": "QFN-60",
        "dimensions": "7x7mm",
        "gpioCount": 30,
        "internalFlashBytes": 2 * 1024 * 1024,
        "externalXipLimitBytes": 16 * 1024 * 1024,
        "sramBytes": 520 * 1024,
        "sramBanks": [
            {"name": "SRAM0", "baseAddress": 0x20000000, "sizeBytes": 64 * 1024, "striped": True},
            {"name": "SRAM1", "baseAddress": 0x20010000, "sizeBytes": 64 * 1024, "striped": True},
            {"name": "SRAM2", "baseAddress": 0x20020000, "sizeBytes": 64 * 1024, "striped": True},
            {"name": "SRAM3", "baseAddress": 0x20030000, "sizeBytes": 64 * 1024, "striped": True},
            {"name": "SRAM4", "baseAddress": 0x20040000, "sizeBytes": 64 * 1024, "striped": True},
            {"name": "SRAM5", "baseAddress": 0x20050000, "sizeBytes": 64 * 1024, "striped": True},
            {"name": "SRAM6", "baseAddress": 0x20060000, "sizeBytes": 64 * 1024, "striped": True},
            {"name": "SRAM7", "baseAddress": 0x20070000, "sizeBytes": 64 * 1024, "striped": True},
            {"name": "SRAM8", "baseAddress": 0x20080000, "sizeBytes": 4 * 1024, "striped": False},
            {"name": "SRAM9", "baseAddress": 0x20081000, "sizeBytes": 4 * 1024, "striped": False}
        ],
        "bootRomBytes": 32 * 1024,
        "bootRomBase": 0x00000000,
        "flashXipBase": 0x10000000,
        "applicationCoreCount": 2,
        "bootArchitectures": ["ARM_CORTEX_M33", "HAZARD3_RISCV"],
        "architectureSelectionMode": "IMAGE_DEF_SELECTABLE_AT_BOOT",
        "pioBlocks": 3,
        "pioStateMachinesPerBlock": 4,
        "hasAtomicAliases": True,
        "atomicAliasBase": 0x50000000,
        "sioBase": 0xD0000000,
        "securityCapabilities": ["ARM_TRUSTZONE", "OTP_8KB", "HARDWARE_SHA256", "TRNG", "SECURE_BOOT"],
        "peripheralNames": [
            "ADC", "BUSCTRL", "CLOCKS", "DMA", "HSTX", "I2C0", "I2C1", "IO_BANK0", "IO_QSPI",
            "OTP", "PADS_BANK0", "PADS_QSPI", "PIO0", "PIO1", "PIO2", "PLL_SYS", "PLL_USB",
            "POWMAN", "PWM", "QMI", "RESETS", "ROSC", "RTC", "SHA256", "SIO", "SPI0", "SPI1",
            "SYSCONFIG", "SYSINFO", "TBMAN", "TICKS", "TIMER0", "TIMER1", "TRNG", "UART0",
            "UART1", "USB", "VREG_AND_CHIP_RESET", "WATCHDOG", "XIP_AUX", "XIP_CTRL", "XOSC"
        ],
        "supportState": "PLANNED",
        "sourceProvenance": {
            "title": "RP2350 Datasheet: A microcontroller by Raspberry Pi (RP2354 2MB stacked flash variant)",
            "revision": "release 1 (2024-08)",
            "url": "https://datasheets.raspberrypi.com/rp2350/rp2350-datasheet.pdf",
            "license": "CC-BY-ND-4.0 / Hardware Documentation License"
        }
    },
    {
        "recordId": "rp:silicon:rp2354b",
        "exactPart": "RP2354B",
        "series": "RP2354",
        "vendor": "Raspberry Pi Ltd",
        "package": "QFN-80",
        "dimensions": "10x10mm",
        "gpioCount": 48,
        "internalFlashBytes": 2 * 1024 * 1024,
        "externalXipLimitBytes": 16 * 1024 * 1024,
        "sramBytes": 520 * 1024,
        "sramBanks": [
            {"name": "SRAM0", "baseAddress": 0x20000000, "sizeBytes": 64 * 1024, "striped": True},
            {"name": "SRAM1", "baseAddress": 0x20010000, "sizeBytes": 64 * 1024, "striped": True},
            {"name": "SRAM2", "baseAddress": 0x20020000, "sizeBytes": 64 * 1024, "striped": True},
            {"name": "SRAM3", "baseAddress": 0x20030000, "sizeBytes": 64 * 1024, "striped": True},
            {"name": "SRAM4", "baseAddress": 0x20040000, "sizeBytes": 64 * 1024, "striped": True},
            {"name": "SRAM5", "baseAddress": 0x20050000, "sizeBytes": 64 * 1024, "striped": True},
            {"name": "SRAM6", "baseAddress": 0x20060000, "sizeBytes": 64 * 1024, "striped": True},
            {"name": "SRAM7", "baseAddress": 0x20070000, "sizeBytes": 64 * 1024, "striped": True},
            {"name": "SRAM8", "baseAddress": 0x20080000, "sizeBytes": 4 * 1024, "striped": False},
            {"name": "SRAM9", "baseAddress": 0x20081000, "sizeBytes": 4 * 1024, "striped": False}
        ],
        "bootRomBytes": 32 * 1024,
        "bootRomBase": 0x00000000,
        "flashXipBase": 0x10000000,
        "applicationCoreCount": 2,
        "bootArchitectures": ["ARM_CORTEX_M33", "HAZARD3_RISCV"],
        "architectureSelectionMode": "IMAGE_DEF_SELECTABLE_AT_BOOT",
        "pioBlocks": 3,
        "pioStateMachinesPerBlock": 4,
        "hasAtomicAliases": True,
        "atomicAliasBase": 0x50000000,
        "sioBase": 0xD0000000,
        "securityCapabilities": ["ARM_TRUSTZONE", "OTP_8KB", "HARDWARE_SHA256", "TRNG", "SECURE_BOOT"],
        "peripheralNames": [
            "ADC", "BUSCTRL", "CLOCKS", "DMA", "HSTX", "I2C0", "I2C1", "IO_BANK0", "IO_QSPI",
            "OTP", "PADS_BANK0", "PADS_QSPI", "PIO0", "PIO1", "PIO2", "PLL_SYS", "PLL_USB",
            "POWMAN", "PWM", "QMI", "RESETS", "ROSC", "RTC", "SHA256", "SIO", "SPI0", "SPI1",
            "SYSCONFIG", "SYSINFO", "TBMAN", "TICKS", "TIMER0", "TIMER1", "TRNG", "UART0",
            "UART1", "USB", "VREG_AND_CHIP_RESET", "WATCHDOG", "XIP_AUX", "XIP_CTRL", "XOSC"
        ],
        "supportState": "PLANNED",
        "sourceProvenance": {
            "title": "RP2350 Datasheet: A microcontroller by Raspberry Pi (RP2354 2MB stacked flash variant)",
            "revision": "release 1 (2024-08)",
            "url": "https://datasheets.raspberrypi.com/rp2350/rp2350-datasheet.pdf",
            "license": "CC-BY-ND-4.0 / Hardware Documentation License"
        }
    }
]

# Official Raspberry Pi board profiles layering external flash and wireless components
BOARD_PROFILES = [
    {
        "profileId": "pico",
        "boardName": "Raspberry Pi Pico",
        "vendor": "Raspberry Pi Ltd",
        "siliconPart": "RP2040",
        "externalFlashBytes": 2 * 1024 * 1024,
        "externalFlashChip": "Winbond W25Q16JV",
        "externalFlashInterface": "QSPI",
        "wirelessChip": None,
        "ledGpio": 25,
        "supportState": "PLANNED",
        "documentationUrl": "https://datasheets.raspberrypi.com/pico/pico-datasheet.pdf"
    },
    {
        "profileId": "pico_w",
        "boardName": "Raspberry Pi Pico W",
        "vendor": "Raspberry Pi Ltd",
        "siliconPart": "RP2040",
        "externalFlashBytes": 2 * 1024 * 1024,
        "externalFlashChip": "Winbond W25Q16JV",
        "externalFlashInterface": "QSPI",
        "wirelessChip": {
            "model": "Infineon CYW43439",
            "interfaces": ["SPI", "PIO"],
            "wifi": "802.11b/g/n (2.4 GHz)",
            "bluetooth": "5.2"
        },
        "ledGpio": None,
        "supportState": "PLANNED",
        "documentationUrl": "https://datasheets.raspberrypi.com/picow/pico-w-datasheet.pdf"
    },
    {
        "profileId": "pico2",
        "boardName": "Raspberry Pi Pico 2",
        "vendor": "Raspberry Pi Ltd",
        "siliconPart": "RP2350A",
        "externalFlashBytes": 4 * 1024 * 1024,
        "externalFlashChip": "Winbond W25Q32RV",
        "externalFlashInterface": "QMI",
        "wirelessChip": None,
        "ledGpio": 25,
        "supportState": "PLANNED",
        "documentationUrl": "https://datasheets.raspberrypi.com/pico-2/pico-2-datasheet.pdf"
    },
    {
        "profileId": "pico2_w",
        "boardName": "Raspberry Pi Pico 2 W",
        "vendor": "Raspberry Pi Ltd",
        "siliconPart": "RP2350A",
        "externalFlashBytes": 4 * 1024 * 1024,
        "externalFlashChip": "Winbond W25Q32RV",
        "externalFlashInterface": "QMI",
        "wirelessChip": {
            "model": "Infineon CYW43439",
            "interfaces": ["SPI", "PIO"],
            "wifi": "802.11b/g/n (2.4 GHz)",
            "bluetooth": "5.2"
        },
        "ledGpio": None,
        "supportState": "PLANNED",
        "documentationUrl": "https://datasheets.raspberrypi.com/pico-2-w/pico-2-w-datasheet.pdf"
    }
]


def canonical_json(obj: object) -> str:
    return json.dumps(obj, sort_keys=True, indent=2) + "\n"


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def generate(out_dir: Path) -> dict[str, str]:
    out_dir.mkdir(parents=True, exist_ok=True)

    catalog_data = {
        "$schema": RP_CATALOG_SCHEMA,
        "catalogId": "raspberrypi.rp-silicon",
        "vendor": "Raspberry Pi Ltd",
        "generator": "generate-rp-catalog.py",
        "recordCount": len(SILICON_RECORDS),
        "records": sorted(SILICON_RECORDS, key=lambda r: r["recordId"])
    }
    catalog_json = canonical_json(catalog_data)
    catalog_sha = sha256_text(catalog_json)
    catalog_file = out_dir / "catalog.json"
    catalog_sha_file = out_dir / "catalog.sha256"
    catalog_file.write_text(catalog_json, encoding="utf-8")
    catalog_sha_file.write_text(f"{catalog_sha}  catalog.json\n", encoding="utf-8")

    board_data = {
        "$schema": RP_BOARD_PROFILES_SCHEMA,
        "catalogId": "raspberrypi.rp-boards",
        "vendor": "Raspberry Pi Ltd",
        "generator": "generate-rp-catalog.py",
        "profileCount": len(BOARD_PROFILES),
        "profiles": sorted(BOARD_PROFILES, key=lambda p: p["profileId"])
    }
    board_json = canonical_json(board_data)
    board_sha = sha256_text(board_json)
    board_file = out_dir / "board-profiles.json"
    board_sha_file = out_dir / "board-profiles.sha256"
    board_file.write_text(board_json, encoding="utf-8")
    board_sha_file.write_text(f"{board_sha}  board-profiles.json\n", encoding="utf-8")

    return {
        "catalogSha256": catalog_sha,
        "boardProfilesSha256": board_sha,
        "siliconCount": len(SILICON_RECORDS),
        "boardCount": len(BOARD_PROFILES)
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR,
                        help="Target directory for generated RP catalogs")
    args = parser.parse_args()

    results = generate(args.out_dir)
    print(json.dumps(results, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
