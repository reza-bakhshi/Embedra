#!/usr/bin/env python3
"""Unit tests for Nordic peripheral pack generation and integrity."""

import hashlib
import json
from pathlib import Path
import unittest

PACKS_DIR = Path("catalogs/nordic/packs")


class TestNordicPacks(unittest.TestCase):

    def test_all_five_series_packs_exist(self):
        for series in ("nrf51", "nrf52", "nrf53", "nrf54", "nrf91"):
            json_path = PACKS_DIR / f"{series}-peripherals.json"
            sha_path = PACKS_DIR / f"{series}-peripherals.sha256"

            self.assertTrue(json_path.is_file(), f"Missing {json_path}")
            self.assertTrue(sha_path.is_file(), f"Missing {sha_path}")

            # Check checksum
            raw = json_path.read_bytes()
            actual_sha = hashlib.sha256(raw).hexdigest()
            expected_sha = sha_path.read_text(encoding="utf-8").strip().split()[0]
            self.assertEqual(expected_sha.lower(), actual_sha.lower())

            # Parse JSON
            data = json.loads(raw.decode("utf-8"))
            self.assertEqual(data["schemaId"], "urn:embedra:schema:nordic-peripheral-pack:1")
            self.assertEqual(data["series"].lower(), series)
            self.assertTrue(len(data["peripherals"]) >= 10)

    def test_easydma_and_cryptocell_definitions(self):
        nrf52_data = json.loads((PACKS_DIR / "nrf52-peripherals.json").read_text(encoding="utf-8"))
        periph_names = {p["name"] for p in nrf52_data["peripherals"]}
        self.assertIn("RADIO", periph_names)
        self.assertIn("UARTE0", periph_names)
        self.assertIn("SPIM0", periph_names)
        self.assertIn("TWIM0", periph_names)
        self.assertIn("CRYPTOCELL_CC310", periph_names)

        nrf53_data = json.loads((PACKS_DIR / "nrf53-peripherals.json").read_text(encoding="utf-8"))
        periph_names_53 = {p["name"] for p in nrf53_data["peripherals"]}
        self.assertIn("SPU", periph_names_53)
        self.assertIn("DPPI_SECURE", periph_names_53)
        self.assertIn("CRYPTOCELL_CC312", periph_names_53)


if __name__ == "__main__":
    unittest.main()
