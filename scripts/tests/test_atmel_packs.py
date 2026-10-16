#!/usr/bin/env python3
"""Unit tests for Atmel / Microchip peripheral pack generation and integrity (T108)."""

import hashlib
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
PACKS_DIR = ROOT / "catalogs" / "atmel" / "packs"
AUDIT_FILE = ROOT / ".embedra" / "evidence" / "tasks" / "T108-source-audit.json"

EXPECTED_PACK_PARTS = [
    "atmega128", "atmega168p", "atmega2560", "atmega328p", "atmega32u4", "atmega88p", "atmega8a",
    "attiny13a", "attiny1614", "attiny2313a", "attiny45", "attiny84", "attiny85",
    "avr128da48", "avr128db48", "avr32da28", "avr64da32",
    "sam3x8e", "samd21e18a", "samd21g18a", "samd51j19a", "same70q21", "sams70n21", "samv71q21"
]


class TestAtmelPacks(unittest.TestCase):

    def test_all_twenty_four_packs_and_checksums_exist(self):
        self.assertTrue(PACKS_DIR.is_dir(), f"Packs directory missing: {PACKS_DIR}")
        for part in EXPECTED_PACK_PARTS:
            json_path = PACKS_DIR / f"{part}-peripherals.json"
            sha_path = PACKS_DIR / f"{part}-peripherals.sha256"

            self.assertTrue(json_path.is_file(), f"Missing pack: {json_path}")
            self.assertTrue(sha_path.is_file(), f"Missing checksum: {sha_path}")

            raw = json_path.read_bytes()
            actual_sha = hashlib.sha256(raw).hexdigest()
            expected_sha = sha_path.read_text(encoding="utf-8").strip().split()[0]
            self.assertEqual(expected_sha.lower(), actual_sha.lower(), f"Checksum mismatch for {part}")

            data = json.loads(raw.decode("utf-8"))
            self.assertEqual(data.get("schemaId"), "urn:embedra:schema:atmel-peripheral-pack:1")
            self.assertIn("peripherals", data)
            self.assertIn("ioPorts", data)
            self.assertIn("fuseMap", data)
            self.assertIn("interrupts", data)
            self.assertTrue(len(data["peripherals"]) > 0, f"No peripherals in {part}")

    def test_atmega328p_pack_semantics(self):
        pack_path = PACKS_DIR / "atmega328p-peripherals.json"
        data = json.loads(pack_path.read_bytes().decode("utf-8"))

        self.assertEqual("ATmega328P", data["catalogPart"])
        self.assertEqual("ATmega", data["series"])
        self.assertEqual("DATA", data["addressSpace"])

        # IO Ports
        io_port_names = {p["name"] for p in data["ioPorts"]}
        self.assertEqual({"PORTB", "PORTC", "PORTD"}, io_port_names)
        portb = next(p for p in data["ioPorts"] if p["name"] == "PORTB")
        self.assertEqual(8, portb["pinCount"])
        self.assertEqual("PORTB", portb["dataRegister"])
        self.assertEqual("DDRB", portb["directionRegister"])
        self.assertEqual("PINB", portb["inputRegister"])

        # Fuse map
        fuse_map = data["fuseMap"]
        self.assertEqual("PINNED", fuse_map["state"])
        byte_names = {b["name"] for b in fuse_map["bytes"]}
        self.assertTrue({"LOW", "HIGH", "EXTENDED", "LOCKBIT"}.issubset(byte_names))

        # Interrupts
        self.assertEqual(26, len(data["interrupts"]))
        self.assertEqual("RESET", data["interrupts"][0]["name"])

    def test_samd21g18a_pack_semantics(self):
        pack_path = PACKS_DIR / "samd21g18a-peripherals.json"
        data = json.loads(pack_path.read_bytes().decode("utf-8"))

        self.assertEqual("SAMD21G18A", data["catalogPart"])
        self.assertEqual("SAMD", data["series"])
        self.assertEqual("PERIPHERAL", data["addressSpace"])

        periph_names = {p["name"] for p in data["peripherals"]}
        self.assertTrue({"PORT", "PM", "SYSCTRL", "GCLK", "WDT", "RTC", "DMAC", "ADC"}.issubset(periph_names))

        # Check PORT peripheral
        port_periph = next(p for p in data["peripherals"] if p["name"] == "PORT")
        self.assertEqual(0x41004400, port_periph["baseAddress"])

    def test_source_audit_document(self):
        self.assertTrue(AUDIT_FILE.is_file(), f"Audit file missing: {AUDIT_FILE}")
        audit = json.loads(AUDIT_FILE.read_bytes().decode("utf-8"))
        self.assertEqual("urn:embedra:schema:atmel-peripheral-pack:1", audit["schemaId"])
        self.assertEqual(24, len(audit["devices"]))
        device_catalog_parts = {d["catalogPart"] for d in audit["devices"]}
        for part in ["ATmega328P", "ATmega2560", "ATtiny85", "SAMD21G18A", "SAME70Q21", "SAM3X8E"]:
            self.assertIn(part, device_catalog_parts)


if __name__ == "__main__":
    unittest.main()
