#!/usr/bin/env python3
"""Automated verification for T104 Atmel / Microchip capability matrix and audit.

Validates that:
1. Matrix file exists and conforms to urn:embedra:schema:atmel-capability-matrix:1.
2. Covers all five series (ATmega, ATtiny, AVR-Dx, SAMD, SAME).
3. Covers all 27 curated exact silicon parts with explicit specifications,
   including all mandatory parts:
   ATmega328P, ATmega2560, ATmega32U4, ATmega128,
   ATtiny85, ATtiny13A, ATtiny84, ATtiny1614,
   AVR128DA48, AVR128DB48,
   SAMD21G18A, SAMD51J19A, SAME70Q21, SAM3X8E.
4. Memory regions satisfy physical invariants:
   - AVR Classic: Code Flash 0x00000000, Data space SRAM, EEPROM.
   - AVR Unified: Flash aliased to data space 0x8000, SRAM 0x4000.
   - SAM: 32-bit linear address spaces.
5. Vector table strides match part architecture (2-byte RJMP for <=8KB classic, 4-byte JMP for >8KB / Cortex-M).
6. All parts initialize in the PLANNED state per ATMEL-010.
7. The audit document docs/atmel-audit.md exists and covers all required sections.
"""

import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
MATRIX_PATH = ROOT / ".embedra" / "evidence" / "tasks" / "T104-atmel-capability-matrix.json"
CATALOG_PATH = ROOT / "catalogs" / "atmel" / "2026-10-14" / "catalog.json"
AUDIT_DOC = ROOT / "docs" / "atmel-audit.md"

EXPECTED_SERIES = {"ATmega", "ATtiny", "AVR-Dx", "SAMD", "SAME"}

MANDATORY_PARTS = [
    "ATmega328P", "ATmega2560", "ATmega32U4", "ATmega128",
    "ATtiny85", "ATtiny13A", "ATtiny84", "ATtiny1614",
    "AVR128DA48", "AVR128DB48",
    "SAMD21G18A", "SAMD51J19A", "SAME70Q21", "SAM3X8E"
]


class AtmelAuditTest(unittest.TestCase):
    def setUp(self):
        self.assertTrue(MATRIX_PATH.is_file(), f"Matrix file missing: {MATRIX_PATH}")
        self.assertTrue(CATALOG_PATH.is_file(), f"Catalog file missing: {CATALOG_PATH}")
        self.assertTrue(AUDIT_DOC.is_file(), f"Audit doc missing: {AUDIT_DOC}")

        with MATRIX_PATH.open(encoding="utf-8") as f:
            self.matrix = json.load(f)

        with CATALOG_PATH.open(encoding="utf-8") as f:
            self.catalog = json.load(f)

    def test_schema_and_metadata(self):
        self.assertEqual("urn:embedra:schema:atmel-capability-matrix:1", self.matrix.get("schemaId"))
        self.assertEqual("urn:embedra:schema:atmel-catalog:1", self.catalog.get("$schema"))

        metadata = self.matrix.get("metadata", {})
        self.assertEqual("T104", metadata.get("task"))
        self.assertEqual(5, metadata.get("totalSeriesCount"))
        self.assertEqual(27, metadata.get("totalExactPartCount"))
        self.assertGreaterEqual(len(metadata.get("authoritativeReferences", [])), 5)

    def test_covers_all_five_series(self):
        series_set = {s["series"] for s in self.matrix.get("series", [])}
        self.assertEqual(EXPECTED_SERIES, series_set)

    def test_covers_mandatory_and_total_parts(self):
        parts = self.matrix.get("parts", [])
        self.assertEqual(27, len(parts))

        part_names = {p["exactPart"] for p in parts}
        self.assertEqual(27, len(part_names), "Part names must be unique")

        for mandatory in MANDATORY_PARTS:
            self.assertIn(mandatory, part_names, f"Mandatory part missing: {mandatory}")

        for part in parts:
            self.assertEqual("PLANNED", part.get("supportState"),
                             f"Part {part['exactPart']} must initialize as PLANNED")
            self.assertIn("package", part)
            self.assertIn("datasheet", part)
            self.assertIn("flashBytes", part)
            self.assertIn("ramBytes", part)
            self.assertIn("family", part)
            self.assertIn("ghidraLanguage", part)
            self.assertIn("vectorStrideBytes", part)

    def test_memory_invariants(self):
        for part in self.matrix.get("parts", []):
            pn = part["exactPart"]
            flash_bytes = part["flashBytes"]
            ram_bytes = part["ramBytes"]

            flash_start = int(part["flashRange"]["start"], 16)
            flash_end = int(part["flashRange"]["end"], 16)
            self.assertEqual(flash_bytes, flash_end - flash_start + 1,
                             f"{pn}: flashRange extent must match flashBytes")

            ram_start = int(part["ramRange"]["start"], 16)
            ram_end = int(part["ramRange"]["end"], 16)
            self.assertEqual(ram_bytes, ram_end - ram_start + 1,
                             f"{pn}: ramRange extent must match ramBytes")

            # Check AVR classic memory spaces
            if part["family"] == "AVR" and part["series"] in ("ATmega", "ATtiny") and part["core"] == "AVR RISC":
                self.assertEqual(0, flash_start, f"{pn}: Flash code space must start at 0")
                self.assertGreater(ram_start, 0x001F, f"{pn}: SRAM must start above R0-R31 register file")
                if part.get("eepromBytes", 0) > 0:
                    eeprom_start = int(part["eepromRange"]["start"], 16)
                    eeprom_end = int(part["eepromRange"]["end"], 16)
                    self.assertEqual(part["eepromBytes"], eeprom_end - eeprom_start + 1)

            # Check AVR Unified Dx
            if part["series"] == "AVR-Dx":
                self.assertEqual(0x4000, ram_start, f"{pn}: Dx SRAM starts at 0x4000")
                self.assertIn("flashDataAlias", part)
                self.assertEqual(0x8000, int(part["flashDataAlias"]["start"], 16))

            # Check SAM 32-bit linear
            if part["family"] == "SAM":
                self.assertIn(flash_start, (0x00000000, 0x00400000, 0x00080000))
                self.assertIn(ram_start, (0x20000000, 0x20400000))

    def test_vector_stride_rules(self):
        for part in self.matrix.get("parts", []):
            pn = part["exactPart"]
            stride = part["vectorStrideBytes"]
            if part["family"] == "AVR" and part["core"] == "AVR RISC":
                if part["flashBytes"] <= 8192:
                    self.assertEqual(2, stride, f"{pn} <= 8KB Flash must have 2-byte vector stride")
                    self.assertEqual("RJMP", part["vectorInstruction"])
                else:
                    self.assertEqual(4, stride, f"{pn} > 8KB Flash must have 4-byte vector stride")
                    self.assertEqual("JMP", part["vectorInstruction"])
            else:
                self.assertEqual(4, stride, f"{pn} must have 4-byte vector stride")

    def test_audit_doc_content(self):
        content = AUDIT_DOC.read_text(encoding="utf-8")
        required_substrings = [
            "ATMEL-001",
            "ATMEL-010",
            "Harvard",
            "ATmega328P",
            "ATmega2560",
            "ATtiny85",
            "SAMD21G18A",
            "SAME70Q21",
            "RJMP",
            "BOOTSZ",
            "Optiboot",
            "SAM-BA",
            "Fuses"
        ]
        for sub in required_substrings:
            self.assertIn(sub, content, f"Audit doc missing requirement: {sub}")


if __name__ == "__main__":
    unittest.main()
