#!/usr/bin/env python3
"""Unit tests for the Raspberry Pi catalog generator."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "generate-rp-catalog.py"


def load_generator():
    spec = importlib.util.spec_from_file_location("generate_rp_catalog", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class GenerateRpCatalogTest(unittest.TestCase):
    def setUp(self):
        self.generator = load_generator()

    def test_generation_is_deterministic(self):
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            r1 = self.generator.generate(Path(first))
            r2 = self.generator.generate(Path(second))
            self.assertEqual(r1["catalogSha256"], r2["catalogSha256"])
            self.assertEqual(r1["boardProfilesSha256"], r2["boardProfilesSha256"])
            self.assertEqual(
                (Path(first) / "catalog.json").read_bytes(),
                (Path(second) / "catalog.json").read_bytes())
            self.assertEqual(
                (Path(first) / "board-profiles.json").read_bytes(),
                (Path(second) / "board-profiles.json").read_bytes())

    def test_catalog_contains_authoritative_silicon_records(self):
        with tempfile.TemporaryDirectory() as temp:
            self.generator.generate(Path(temp))
            catalog = json.loads((Path(temp) / "catalog.json").read_text())
            records = {r["exactPart"]: r for r in catalog["records"]}

            expected_parts = {"RP2040", "RP2350A", "RP2350B", "RP2354A", "RP2354B"}
            self.assertEqual(expected_parts, set(records.keys()))

            # All records must start in PLANNED state
            for r in records.values():
                self.assertEqual("PLANNED", r["supportState"])

            # RP2040 checks
            rp2040 = records["RP2040"]
            self.assertEqual("QFN-56", rp2040["package"])
            self.assertEqual(30, rp2040["gpioCount"])
            self.assertEqual(264 * 1024, rp2040["sramBytes"])
            self.assertEqual(0, rp2040["internalFlashBytes"])
            self.assertEqual(["ARM_CORTEX_M0P"], rp2040["bootArchitectures"])
            self.assertEqual(2, rp2040["pioBlocks"])
            self.assertEqual(16 * 1024, rp2040["bootRomBytes"])

            # RP2350A vs RP2350B package and GPIO differences
            rp2350a = records["RP2350A"]
            rp2350b = records["RP2350B"]
            self.assertEqual("QFN-60", rp2350a["package"])
            self.assertEqual(30, rp2350a["gpioCount"])
            self.assertEqual("QFN-80", rp2350b["package"])
            self.assertEqual(48, rp2350b["gpioCount"])
            self.assertEqual(520 * 1024, rp2350a["sramBytes"])
            self.assertEqual(0, rp2350a["internalFlashBytes"])
            self.assertEqual(["ARM_CORTEX_M33", "HAZARD3_RISCV"], rp2350a["bootArchitectures"])
            self.assertEqual(3, rp2350a["pioBlocks"])

            # RP2354 stacked flash differences
            rp2354a = records["RP2354A"]
            rp2354b = records["RP2354B"]
            self.assertEqual(2 * 1024 * 1024, rp2354a["internalFlashBytes"])
            self.assertEqual(2 * 1024 * 1024, rp2354b["internalFlashBytes"])
            self.assertEqual("QFN-60", rp2354a["package"])
            self.assertEqual("QFN-80", rp2354b["package"])

    def test_board_profiles_reference_cataloged_silicon(self):
        with tempfile.TemporaryDirectory() as temp:
            self.generator.generate(Path(temp))
            catalog = json.loads((Path(temp) / "catalog.json").read_text())
            silicon_parts = {r["exactPart"] for r in catalog["records"]}

            boards = json.loads((Path(temp) / "board-profiles.json").read_text())
            profiles = {p["profileId"]: p for p in boards["profiles"]}

            expected_boards = {"pico", "pico_w", "pico2", "pico2_w"}
            self.assertEqual(expected_boards, set(profiles.keys()))

            for p in profiles.values():
                self.assertIn(p["siliconPart"], silicon_parts)
                self.assertEqual("PLANNED", p["supportState"])

            # Pico & Pico W use RP2040 with 2MB flash
            self.assertEqual("RP2040", profiles["pico"]["siliconPart"])
            self.assertEqual(2 * 1024 * 1024, profiles["pico"]["externalFlashBytes"])
            self.assertIsNone(profiles["pico"]["wirelessChip"])
            self.assertEqual("Infineon CYW43439", profiles["pico_w"]["wirelessChip"]["model"])

            # Pico 2 & Pico 2 W use RP2350A with 4MB flash
            self.assertEqual("RP2350A", profiles["pico2"]["siliconPart"])
            self.assertEqual(4 * 1024 * 1024, profiles["pico2"]["externalFlashBytes"])
            self.assertIsNone(profiles["pico2"]["wirelessChip"])
            self.assertEqual("Infineon CYW43439", profiles["pico2_w"]["wirelessChip"]["model"])


if __name__ == "__main__":
    unittest.main()
