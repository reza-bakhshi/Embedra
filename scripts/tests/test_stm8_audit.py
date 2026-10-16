#!/usr/bin/env python3
"""Automated verification for T088 STM8 capability matrix and audit.

Validates that:
1. Matrix file exists and conforms to urn:embedra:schema:stm8-capability-matrix:1.
2. Covers all four STM8 families (STM8S, STM8L, STM8A, STM8T).
3. Covers all 32 curated exact silicon parts with explicit specifications.
4. Memory regions (Flash, RAM, EEPROM, Option bytes, Peripherals, Boot ROM)
   satisfy physical invariants and never overlap.
5. Vector table is anchored at 0x008000, contains 32 4-byte entries with opcode 0x82.
6. All parts initialize in the PLANNED state per STM8-010.
7. Segregation from 32-bit Cortex-M STM32 is explicitly documented and enforced.
8. The audit document docs/stm8-audit.md exists and covers all required sections.
"""

import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
MATRIX_PATH = ROOT / ".embedra" / "evidence" / "tasks" / "T088-stm8-capability-matrix.json"
AUDIT_DOC = ROOT / "docs" / "stm8-audit.md"

EXPECTED_FAMILIES = {"STM8S", "STM8L", "STM8A", "STM8T"}


class Stm8AuditTest(unittest.TestCase):
    def setUp(self):
        self.assertTrue(MATRIX_PATH.is_file(), f"Matrix file missing: {MATRIX_PATH}")
        self.assertTrue(AUDIT_DOC.is_file(), f"Audit doc missing: {AUDIT_DOC}")

        with MATRIX_PATH.open(encoding="utf-8") as f:
            self.matrix = json.load(f)

    def test_schema_and_metadata(self):
        self.assertEqual("urn:embedra:schema:stm8-capability-matrix:1", self.matrix.get("schemaId"))
        metadata = self.matrix.get("metadata", {})
        self.assertEqual("T088", metadata.get("task"))
        self.assertEqual(4, metadata.get("totalFamilyCount"))
        self.assertEqual(32, metadata.get("totalExactPartCount"))
        self.assertGreaterEqual(len(metadata.get("authoritativeReferences", [])), 4)

    def test_covers_all_four_families(self):
        families = {f["family"] for f in self.matrix.get("families", [])}
        self.assertEqual(EXPECTED_FAMILIES, families)

    def test_covers_thirty_two_exact_parts(self):
        parts = self.matrix.get("parts", [])
        self.assertEqual(32, len(parts))

        part_names = {p["exactPart"] for p in parts}
        self.assertEqual(32, len(part_names), "Part names must be unique")

        # Verify family distribution: 14 STM8S, 8 STM8L, 7 STM8A, 3 STM8T
        stm8s_parts = [p for p in parts if p["family"] == "STM8S"]
        stm8l_parts = [p for p in parts if p["family"] == "STM8L"]
        stm8a_parts = [p for p in parts if p["family"] == "STM8A"]
        stm8t_parts = [p for p in parts if p["family"] == "STM8T"]

        self.assertEqual(14, len(stm8s_parts))
        self.assertEqual(8, len(stm8l_parts))
        self.assertEqual(7, len(stm8a_parts))
        self.assertEqual(3, len(stm8t_parts))

        for part in parts:
            self.assertEqual("PLANNED", part.get("supportState"),
                             f"Part {part['exactPart']} must initialize as PLANNED")
            self.assertIn("package", part)
            self.assertIn("datasheet", part)
            self.assertGreater(len(part.get("peripherals", [])), 0)

    def test_memory_invariants_and_non_overlap(self):
        for part in self.matrix.get("parts", []):
            pn = part["exactPart"]
            flash_bytes = part["flashBytes"]
            ram_bytes = part["ramBytes"]
            eeprom_bytes = part["eepromBytes"]

            flash_start = int(part["flashRange"]["start"], 16)
            flash_end = int(part["flashRange"]["end"], 16)
            ram_start = int(part["ramRange"]["start"], 16)
            ram_end = int(part["ramRange"]["end"], 16)
            eeprom_start = int(part["eepromRange"]["start"], 16)
            eeprom_end = int(part["eepromRange"]["end"], 16)
            opt_start = int(part["optionBytesRange"]["start"], 16)
            opt_end = int(part["optionBytesRange"]["end"], 16)
            boot_start = int(part["bootRomRange"]["start"], 16)
            boot_end = int(part["bootRomRange"]["end"], 16)
            peri_start = int(part["peripheralsRange"]["start"], 16)
            peri_end = int(part["peripheralsRange"]["end"], 16)

            # Invariant bases
            self.assertEqual(0x008000, flash_start, f"{pn} flash must start at 0x8000")
            self.assertEqual(flash_start + flash_bytes - 1, flash_end, f"{pn} flash length")
            self.assertEqual(0x000000, ram_start, f"{pn} ram must start at 0x0000")
            self.assertEqual(ram_start + ram_bytes - 1, ram_end, f"{pn} ram length")
            self.assertEqual(0x004000, eeprom_start, f"{pn} eeprom must start at 0x4000")
            self.assertEqual(eeprom_start + eeprom_bytes - 1, eeprom_end, f"{pn} eeprom length")
            self.assertEqual(0x004800, opt_start, f"{pn} option bytes base")
            self.assertEqual(0x006000, boot_start, f"{pn} boot rom base")
            self.assertEqual(0x0067FF, boot_end, f"{pn} boot rom end")
            self.assertEqual(0x005000, peri_start, f"{pn} peripherals base")
            self.assertEqual(0x0057FF, peri_end, f"{pn} peripherals end")

            # Non-overlap checks
            self.assertLess(ram_end, eeprom_start, f"{pn} RAM must not overlap EEPROM")
            self.assertLess(eeprom_end, opt_start, f"{pn} EEPROM must not overlap option bytes")
            self.assertLess(opt_end, peri_start, f"{pn} Option bytes must not overlap peripherals")
            self.assertLess(peri_end, boot_start, f"{pn} Peripherals must not overlap boot rom")
            self.assertLess(boot_end, flash_start, f"{pn} Boot rom must not overlap flash")

    def test_vector_table_architecture(self):
        vt = self.matrix.get("vectorTable", [])
        self.assertEqual(32, len(vt))

        for idx, entry in enumerate(vt):
            self.assertEqual(idx, entry["slot"])
            expected_offset = 0x008000 + (idx * 4)
            actual_offset = int(entry["offset"], 16)
            self.assertEqual(expected_offset, actual_offset, f"Vector slot {idx} offset")
            self.assertIn("name", entry)

        invariants = self.matrix.get("invariants", {})
        self.assertEqual("0x008000", invariants.get("vectorTableBase"))
        self.assertEqual(32, invariants.get("vectorTableSlots"))
        self.assertEqual(4, invariants.get("vectorEntryBytes"))
        self.assertEqual("0x82", invariants.get("vectorOpcode"))
        self.assertEqual("BIG_ENDIAN", invariants.get("endianness"))

    def test_stm32_segregation(self):
        seg = self.matrix.get("stm32Segregation", {})
        self.assertTrue(seg.get("isolatedFromCortexM"))
        self.assertGreaterEqual(len(seg.get("differences", [])), 4)

    def test_audit_document_exists_and_contains_required_sections(self):
        content = AUDIT_DOC.read_text(encoding="utf-8")
        self.assertIn("STM8 8-Bit MCU Family Layout, Vector & Architectural Audit", content)
        self.assertIn("Scope and Pinned Authoritative Baselines", content)
        self.assertIn("Documentation Provenance & License Analysis", content)
        self.assertIn("CPU Core Architecture & Execution Model", content)
        self.assertIn("Unified Linear Memory Map & Invariants", content)
        self.assertIn("Interrupt Vector Table Architecture", content)
        self.assertIn("Curated Exact-Part Allowlist (32 Silicon Parts)", content)
        self.assertIn("Ghidra Language Binding Specification", content)
        self.assertIn("Strict Segregation from STM32 Architecture", content)
        self.assertIn("Unknowns, Documentation Gaps & Preliminary Notes", content)

        for fam in EXPECTED_FAMILIES:
            self.assertIn(fam, content)


if __name__ == "__main__":
    unittest.main()
