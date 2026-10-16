#!/usr/bin/env python3
"""Automated verification for T080 ESP full-flash capability matrix and audit.

Validates that:
1. 100% of the 14 cataloged ESP32-branded series are covered in the capability matrix.
2. All 53 cataloged silicon parts from catalogs/espressif/2026-09-23/catalog.json are mapped.
3. Bootloader offsets match authoritative specs (0x1000 for ESP32; 0x0000 for all others).
4. Default partition table offset is 0x8000 for all series.
5. Chip IDs agree with the bundled espressif-chip-ids.tsv.
6. ESP8266 is explicitly segregated and excluded from ESP32 full-flash series.
7. Current S3 hardcoded assumptions across shared classes are inventoried.
8. The audit document docs/esp-full-flash-audit.md exists and covers all required sections.
"""

import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
MATRIX_PATH = ROOT / ".embedra" / "evidence" / "tasks" / "T080-capability-matrix.json"
AUDIT_DOC = ROOT / "docs" / "esp-full-flash-audit.md"
CATALOG_PATH = ROOT / "catalogs" / "espressif" / "2026-09-23" / "catalog.json"
CHIP_IDS_TSV = ROOT / "src" / "main" / "resources" / "io" / "github" / "rezabakhshi" / "embedra" / "targets" / "esp" / "espressif-chip-ids.tsv"

EXPECTED_SERIES = {
    "ESP32", "ESP32-S2", "ESP32-S3", "ESP32-S31", "ESP32-P4",
    "ESP32-C2", "ESP32-C3", "ESP32-C5", "ESP32-C6", "ESP32-C61",
    "ESP32-E22", "ESP32-H2", "ESP32-H21", "ESP32-H4"
}


class EspFullFlashAuditTest(unittest.TestCase):
    def setUp(self):
        self.assertTrue(MATRIX_PATH.is_file(), f"Matrix file missing: {MATRIX_PATH}")
        self.assertTrue(AUDIT_DOC.is_file(), f"Audit doc missing: {AUDIT_DOC}")
        self.assertTrue(CATALOG_PATH.is_file(), f"Catalog file missing: {CATALOG_PATH}")
        self.assertTrue(CHIP_IDS_TSV.is_file(), f"Chip IDs TSV missing: {CHIP_IDS_TSV}")

        with MATRIX_PATH.open() as f:
            self.matrix = json.load(f)
        with CATALOG_PATH.open() as f:
            self.catalog = json.load(f)

    def test_covers_all_fourteen_esp32_series(self):
        matrix_series = {entry["series"] for entry in self.matrix["series"]}
        self.assertEqual(EXPECTED_SERIES, matrix_series)
        self.assertEqual(14, len(self.matrix["series"]))

    def test_covers_all_fifty_three_silicon_parts(self):
        catalog_silicon = [r for r in self.catalog["records"] if r.get("kind") == "SILICON"]
        self.assertEqual(53, len(catalog_silicon))

        matrix_parts = {p["exactPart"]: p for p in self.matrix["siliconParts"]}
        self.assertEqual(53, len(matrix_parts))

        for part in catalog_silicon:
            pn = part["exactPart"]
            self.assertIn(pn, matrix_parts, f"Silicon part missing from matrix: {pn}")
            self.assertEqual(part["series"], matrix_parts[pn]["series"])
            self.assertEqual(part.get("embeddedFlashMb", "N/A"), matrix_parts[pn]["embeddedFlashMb"])
            self.assertEqual(part.get("embeddedPsramMb", "N/A"), matrix_parts[pn]["embeddedPsramMb"])

    def test_bootloader_offsets_match_authoritative_rules(self):
        for entry in self.matrix["series"]:
            ser = entry["series"]
            if ser == "ESP32":
                self.assertEqual("0x1000", entry["bootloaderOffset"],
                                 "Original ESP32 must have bootloader offset 0x1000")
            else:
                self.assertEqual("0x0000", entry["bootloaderOffset"],
                                 f"{ser} must have bootloader offset 0x0000")

    def test_partition_table_default_offsets(self):
        for entry in self.matrix["series"]:
            self.assertEqual("0x8000", entry["defaultPartitionTableOffset"],
                             f"{entry['series']} default partition offset must be 0x8000")

    def test_chip_ids_match_registry(self):
        tsv_chip_ids = {}
        for line in CHIP_IDS_TSV.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            chip_id = int(parts[0])
            display_name = parts[2]
            tsv_chip_ids[display_name] = chip_id

        for entry in self.matrix["series"]:
            disp = entry["displayName"]
            self.assertIn(disp, tsv_chip_ids)
            self.assertEqual(tsv_chip_ids[disp], entry["chipId"])

    def test_esp8266_is_explicitly_segregated(self):
        segregation = self.matrix.get("esp8266Segregation", {})
        self.assertTrue(segregation.get("excludedFromEsp32FullFlash", False))
        self.assertEqual("ESP8266", segregation.get("series"))
        self.assertNotIn("ESP8266", {s["series"] for s in self.matrix["series"]})
        self.assertGreater(len(segregation.get("reasons", [])), 0)

    def test_s3_hardcoded_assumptions_inventoried(self):
        assumptions = self.matrix.get("s3AssumptionsInventory", {})
        self.assertIn("EspFullFlashWorkspacePlanner", assumptions)
        self.assertIn("EspPartitionTableDiscovery", assumptions)
        self.assertIn("EspApplicationImageLoader", assumptions)

    def test_audit_doc_content_sections(self):
        content = AUDIT_DOC.read_text()
        self.assertIn("ESP32-Branded Full-Flash Layout & Architectural Audit", content)
        self.assertIn("Segregation of ESP8266", content)
        self.assertIn("Capability Matrix", content)
        self.assertIn("53 Silicon Parts", content)
        self.assertIn("Inventory of Current S3 Hardcoded Assumptions", content)
        self.assertIn("EspFlashLayoutProvider", content)
        self.assertIn("EspFlashLayoutProfile", content)
        for ser in EXPECTED_SERIES:
            self.assertIn(ser, content)


if __name__ == "__main__":
    unittest.main()
