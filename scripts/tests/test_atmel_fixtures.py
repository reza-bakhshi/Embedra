#!/usr/bin/env python3
"""Automated verification for T105 Atmel / Microchip fixtures and official-tool oracles.

Validates that:
1. Bare-metal application fixtures (BIN, HEX, ELF) exist for representative parts
   (ATmega328P, ATmega2560, ATtiny85, SAMD21G18A, SAME70Q21) with matching manifests and oracles.
2. Bootloader and composite fixtures exist:
   - atmega328p_optiboot (BIN, HEX, ELF at 0x7E00)
   - atmega328p_composite (HEX with app at 0x0000 and Optiboot at 0x7E00)
   - same70q21_samba (BIN, HEX at 0x00800000)
3. AVR vector table encoding:
   - 4-byte JMP vectors for ATmega328P and ATmega2560.
   - 2-byte RJMP vectors for ATtiny85.
4. SAM Cortex-M vector table encoding:
   - Initial SP within physical SRAM aperture.
   - Reset handler has Thumb bit set.
5. ELF headers:
   - EM_AVR (83) for AVR targets.
   - EM_ARM (40) for SAM targets.
6. Intel HEX fixtures:
   - Valid checksums and record structures.
7. Malformed fixtures:
   - All 7 malformed fixtures exist with matching manifests and fail-closed oracle diagnostics.
"""

import json
from pathlib import Path
import struct
import unittest

ROOT = Path(__file__).resolve().parents[2]
FIXTURES_DIR = ROOT / "src" / "test" / "resources" / "fixtures" / "atmel"
MALFORMED_DIR = FIXTURES_DIR / "malformed"
ORACLES_DIR = ROOT / "src" / "test" / "resources" / "oracles" / "atmel"
ORACLES_MALFORMED_DIR = ORACLES_DIR / "malformed"

REPRESENTATIVE_PARTS = [
    "atmega328p_app",
    "atmega2560_app",
    "attiny85_app",
    "samd21g18a_app",
    "same70q21_app"
]

MALFORMED_CASES = [
    ("atmel_bad_checksum.hex", "HEX_CHECKSUM_MISMATCH"),
    ("atmel_truncated.hex", "HEX_UNEXPECTED_EOF"),
    ("atmel_overlapping.hex", "MEMORY_OVERLAP_CONFLICT"),
    ("attiny85_invalid_vector.bin", "INVALID_AVR_VECTOR_TABLE"),
    ("samd21_bad_sp.bin", "INVALID_INITIAL_SP"),
    ("same70_truncated.bin", "BINARY_TRUNCATED_VECTOR_TABLE"),
    ("atmega328p_truncated_elf.elf", "ELF_TRUNCATED_HEADER")
]


class AtmelFixtureTest(unittest.TestCase):
    def test_representative_fixtures_exist_with_manifests_and_oracles(self):
        for pfx in REPRESENTATIVE_PARTS:
            for ext in [".bin", ".hex", ".elf"]:
                fpath = FIXTURES_DIR / f"{pfx}{ext}"
                mpath = FIXTURES_DIR / f"{pfx}{ext}.manifest.json"
                self.assertTrue(fpath.is_file(), f"Missing fixture: {fpath}")
                self.assertTrue(mpath.is_file(), f"Missing manifest: {mpath}")

                with mpath.open(encoding="utf-8") as f:
                    man = json.load(f)
                self.assertEqual("REDISTRIBUTABLE", man["redistributionStatus"])
                self.assertIn("T105", man["requirements"])

            oracle_path = ORACLES_DIR / f"{pfx}.json"
            self.assertTrue(oracle_path.is_file(), f"Missing oracle: {oracle_path}")
            with oracle_path.open(encoding="utf-8") as f:
                oracle = json.load(f)
            self.assertIn("part", oracle)
            self.assertIn("vectorTable", oracle)

    def test_bootloader_and_composite_fixtures(self):
        # Optiboot
        for ext in [".bin", ".hex", ".elf"]:
            fpath = FIXTURES_DIR / f"atmega328p_optiboot{ext}"
            mpath = FIXTURES_DIR / f"atmega328p_optiboot{ext}.manifest.json"
            self.assertTrue(fpath.is_file(), f"Missing Optiboot fixture: {fpath}")
            self.assertTrue(mpath.is_file(), f"Missing Optiboot manifest: {mpath}")

        # Composite HEX
        comp_hex = FIXTURES_DIR / "atmega328p_composite.hex"
        comp_man = FIXTURES_DIR / "atmega328p_composite.hex.manifest.json"
        comp_orc = ORACLES_DIR / "atmega328p_composite.json"
        self.assertTrue(comp_hex.is_file())
        self.assertTrue(comp_man.is_file())
        self.assertTrue(comp_orc.is_file())

        content = comp_hex.read_text(encoding="utf-8")
        self.assertIn(":107E0000", content, "Optiboot high flash record must be present in composite")
        self.assertIn(":10000000", content, "Application reset record must be present in composite")

        # SAM-BA ROM
        for ext in [".bin", ".hex"]:
            fpath = FIXTURES_DIR / f"same70q21_samba{ext}"
            mpath = FIXTURES_DIR / f"same70q21_samba{ext}.manifest.json"
            self.assertTrue(fpath.is_file())
            self.assertTrue(mpath.is_file())

    def test_avr_vector_table_encodings(self):
        # ATmega328P: 4-byte JMP (0x0C 0x94)
        m328_bin = (FIXTURES_DIR / "atmega328p_app.bin").read_bytes()
        self.assertEqual(0x0C, m328_bin[0])
        self.assertEqual(0x94, m328_bin[1])

        # ATmega2560: 4-byte JMP (0x0C 0x94)
        m2560_bin = (FIXTURES_DIR / "atmega2560_app.bin").read_bytes()
        self.assertEqual(0x0C, m2560_bin[0])
        self.assertEqual(0x94, m2560_bin[1])

        # ATtiny85: 2-byte RJMP (0xCxxx)
        t85_bin = (FIXTURES_DIR / "attiny85_app.bin").read_bytes()
        first_word = struct.unpack_from("<H", t85_bin, 0)[0]
        self.assertEqual(0xC000, first_word & 0xF000, "ATtiny85 vector must be RJMP (opcode 0xCxxx)")

    def test_sam_cortex_m_vector_tables(self):
        # SAMD21
        samd_bin = (FIXTURES_DIR / "samd21g18a_app.bin").read_bytes()
        samd_sp = struct.unpack_from("<I", samd_bin, 0)[0]
        samd_reset = struct.unpack_from("<I", samd_bin, 4)[0]
        self.assertEqual(0x20008000, samd_sp, "SAMD21 SP must be 0x20008000")
        self.assertEqual(1, samd_reset & 1, "SAMD21 reset handler must have Thumb bit set")

        # SAME70
        same_bin = (FIXTURES_DIR / "same70q21_app.bin").read_bytes()
        same_sp = struct.unpack_from("<I", same_bin, 0)[0]
        same_reset = struct.unpack_from("<I", same_bin, 4)[0]
        self.assertEqual(0x20460000, same_sp, "SAME70 SP must be 0x20460000")
        self.assertEqual(1, same_reset & 1, "SAME70 reset handler must have Thumb bit set")

    def test_elf_machine_types(self):
        # AVR targets: EM_AVR = 83
        for pfx in ["atmega328p_app", "atmega2560_app", "attiny85_app", "atmega328p_optiboot"]:
            elf_data = (FIXTURES_DIR / f"{pfx}.elf").read_bytes()
            self.assertTrue(elf_data.startswith(b"\x7fELF"))
            e_machine = struct.unpack_from("<H", elf_data, 18)[0]
            self.assertEqual(83, e_machine, f"{pfx} must have EM_AVR (83)")

        # ARM targets: EM_ARM = 40
        for pfx in ["samd21g18a_app", "same70q21_app"]:
            elf_data = (FIXTURES_DIR / f"{pfx}.elf").read_bytes()
            self.assertTrue(elf_data.startswith(b"\x7fELF"))
            e_machine = struct.unpack_from("<H", elf_data, 18)[0]
            self.assertEqual(40, e_machine, f"{pfx} must have EM_ARM (40)")

    def test_intel_hex_checksums(self):
        for pfx in ["atmega328p_app", "atmega2560_app", "attiny85_app", "samd21g18a_app", "same70q21_app", "atmega328p_optiboot", "atmega328p_composite"]:
            hpath = FIXTURES_DIR / f"{pfx}.hex"
            lines = [l.strip() for l in hpath.read_text(encoding="utf-8").splitlines() if l.strip()]
            self.assertTrue(lines[-1].startswith(":00000001FF"))
            for line in lines[:-1]:
                self.assertTrue(line.startswith(":"))
                raw = bytes.fromhex(line[1:])
                self.assertEqual(0, sum(raw) & 0xFF, f"Hex checksum failure in {pfx}: {line}")

    def test_malformed_fixtures(self):
        for filename, expected_code in MALFORMED_CASES:
            fpath = MALFORMED_DIR / filename
            mpath = MALFORMED_DIR / f"{filename}.manifest.json"
            base_name = filename.rsplit(".", 1)[0]
            opath = ORACLES_MALFORMED_DIR / f"{base_name}.json"

            self.assertTrue(fpath.is_file(), f"Missing malformed fixture: {fpath}")
            self.assertTrue(mpath.is_file(), f"Missing malformed manifest: {mpath}")
            self.assertTrue(opath.is_file(), f"Missing malformed oracle: {opath}")

            with opath.open(encoding="utf-8") as f:
                oracle = json.load(f)
            self.assertTrue(oracle.get("errorExpected"), f"{filename} must expect error")
            self.assertEqual(expected_code, oracle.get("diagnosticCode"),
                             f"{filename} expected diagnostic code {expected_code}")


if __name__ == "__main__":
    unittest.main()
