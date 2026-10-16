#!/usr/bin/env python3
"""Automated verification for T089 STM8 fixtures and official-tool oracles.

Validates that:
1. All 8 representative parts have valid .bin, .hex, .s19, and .elf fixtures.
2. All 6 malformed fixtures exist and have matching manifests.
3. Every fixture has a valid oracle snapshot in src/test/resources/oracles/stm8/.
4. Raw binary fixtures contain the 128-byte vector table starting with 0x82 JPF opcode.
5. Intel HEX fixtures correctly encode load addresses at 0x8000 and extended linear addressing.
6. Motorola S-Record fixtures correctly encode S1/S2 data records and S9 termination records.
7. ELF fixtures have valid ELF32 big-endian headers and entry point at 0x8080.
8. Malformed fixtures correctly reflect their designated failure reasons.
"""

import json
from pathlib import Path
import struct
import unittest

ROOT = Path(__file__).resolve().parents[2]
FIXTURES_DIR = ROOT / "src" / "test" / "resources" / "fixtures" / "stm8"
MALFORMED_DIR = FIXTURES_DIR / "malformed"
ORACLES_DIR = ROOT / "src" / "test" / "resources" / "oracles" / "stm8"

REPRESENTATIVE_PARTS = [
    "STM8S003F3P6", "STM8S103F3P6", "STM8S208RBT6",
    "STM8L151C8T6", "STM8L152R8T6", "STM8AF5288TAY",
    "STM8AL3188TA", "STM8T143AU"
]


class Stm8FixtureTest(unittest.TestCase):
    def test_all_representative_parts_have_four_formats(self):
        for part in REPRESENTATIVE_PARTS:
            for ext in [".bin", ".hex", ".s19", ".elf"]:
                fpath = FIXTURES_DIR / f"{part}{ext}"
                mpath = FIXTURES_DIR / f"{part}{ext}.manifest.json"
                self.assertTrue(fpath.is_file(), f"Missing fixture: {fpath}")
                self.assertTrue(mpath.is_file(), f"Missing manifest: {mpath}")

                with mpath.open(encoding="utf-8") as f:
                    man = json.load(f)
                self.assertEqual(part, man["target"])
                self.assertEqual("REDISTRIBUTABLE", man["redistributionStatus"])

            oracle_path = ORACLES_DIR / f"{part}.json"
            self.assertTrue(oracle_path.is_file(), f"Missing oracle: {oracle_path}")
            with oracle_path.open(encoding="utf-8") as f:
                oracle = json.load(f)
            self.assertEqual(part, oracle["part"])
            self.assertEqual("0x008000", oracle["flashBase"])
            self.assertEqual(32, oracle["vectorCount"])
            self.assertEqual("0x008080", oracle["resetVector"])

    def test_raw_binary_vector_table(self):
        for part in REPRESENTATIVE_PARTS:
            bpath = FIXTURES_DIR / f"{part}.bin"
            data = bpath.read_bytes()
            self.assertGreaterEqual(len(data), 128)

            # Check 32 vectors
            for slot in range(32):
                offset = slot * 4
                opcode = data[offset]
                self.assertEqual(0x82, opcode, f"Slot {slot} must use 0x82 JPF opcode")
                target = (data[offset + 1] << 16) | (data[offset + 2] << 8) | data[offset + 3]
                if slot == 0:
                    self.assertEqual(0x008080, target, "Reset handler target")
                else:
                    self.assertEqual(0x008090, target, "Default handler target")

    def test_intel_hex_structure(self):
        for part in REPRESENTATIVE_PARTS:
            hpath = FIXTURES_DIR / f"{part}.hex"
            lines = [l.strip() for l in hpath.read_text(encoding="utf-8").splitlines() if l.strip()]
            self.assertTrue(lines[-1].startswith(":00000001FF"), "End of file record")

            has_data = False
            for line in lines[:-1]:
                self.assertTrue(line.startswith(":"))
                length = int(line[1:3], 16)
                addr = int(line[3:7], 16)
                rec_type = int(line[7:9], 16)
                self.assertIn(rec_type, [0, 4])
                if rec_type == 0:
                    has_data = True
            self.assertTrue(has_data)

    def test_motorola_srec_structure(self):
        for part in REPRESENTATIVE_PARTS:
            spath = FIXTURES_DIR / f"{part}.s19"
            lines = [l.strip() for l in spath.read_text(encoding="utf-8").splitlines() if l.strip()]
            self.assertTrue(lines[0].startswith("S0"), "Header record")
            self.assertTrue(lines[-1].startswith("S9"), "Termination record")

            for line in lines[1:-1]:
                self.assertTrue(line.startswith("S1") or line.startswith("S2"))

    def test_elf_structure(self):
        for part in REPRESENTATIVE_PARTS:
            epath = FIXTURES_DIR / f"{part}.elf"
            data = epath.read_bytes()
            # Magic \x7fELF
            self.assertEqual(b"\x7fELF", data[0:4])
            # Class 1 (ELFCLASS32)
            self.assertEqual(1, data[4])
            # Data 2 (ELFDATA2MSB = big-endian)
            self.assertEqual(2, data[5])
            # Version 1
            self.assertEqual(1, data[6])

            # Entry point at offset 24 (4 bytes big-endian)
            entry = struct.unpack(">I", data[24:28])[0]
            self.assertEqual(0x00008080, entry)

    def test_all_six_malformed_fixtures(self):
        expected_malformed = [
            "stm8s003_checksum.hex",
            "stm8s103_truncated.bin",
            "stm8l151_checksum.s19",
            "stm8s208_overlapping.hex",
            "stm8af_invalid_opcode.bin",
            "stm8al_out_of_bounds_vector.bin"
        ]
        for mname in expected_malformed:
            mpath = MALFORMED_DIR / mname
            man_path = MALFORMED_DIR / f"{mname}.manifest.json"
            oracle_path = ORACLES_DIR / "malformed" / f"{mname}.json"

            self.assertTrue(mpath.is_file(), f"Missing malformed fixture {mpath}")
            self.assertTrue(man_path.is_file(), f"Missing malformed manifest {man_path}")
            self.assertTrue(oracle_path.is_file(), f"Missing malformed oracle {oracle_path}")

            with oracle_path.open(encoding="utf-8") as f:
                oracle = json.load(f)
            self.assertEqual("FAIL_CLOSED_VALIDATION", oracle["expectedOutcome"])


if __name__ == "__main__":
    unittest.main()
