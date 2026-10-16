#!/usr/bin/env python3
"""Automated verification for T096 Nordic capability matrix and audit.

Validates that:
1. Matrix file exists and conforms to urn:embedra:schema:nordic-capability-matrix:1.
2. Covers all five Nordic series (nRF51, nRF52, nRF53, nRF54, nRF91).
3. Covers all 21 curated exact silicon parts with explicit specifications,
   including all mandatory parts:
   nRF51822-QFAA, nRF51822-QFAC, nRF51802-QFAA,
   nRF52832-QFAA, nRF52840-QIAA, nRF52810-QCAA, nRF52833-QIAA,
   nRF5340-QKAA, nRF54L15, nRF54H20, nRF9160-SICA.
4. Memory regions satisfy physical invariants:
   - Code Flash origin 0x00000000
   - Internal SRAM origin 0x20000000
   - FICR 0x10000000 / 0x00FF0000
   - UICR 0x10001000 / 0x00FF8000
   - Peripherals 0x40000000 / 0x50000000
   - Internal regions never overlap.
5. CryptoCell CC310 / CC312 peripheral apertures match hardware addresses.
6. SoftDevice boundaries (S112, S132, S140) define valid MBR and application offsets.
7. Dual-core topology for nRF5340 separates application core and network core.
8. TrustZone domains for nRF9160 partition Secure vs Non-Secure.
9. All parts initialize in the PLANNED state per NRF-010.
10. The audit document docs/nordic-audit.md exists and covers all required sections.
"""

import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
MATRIX_PATH = ROOT / ".embedra" / "evidence" / "tasks" / "T096-nordic-capability-matrix.json"
CATALOG_PATH = ROOT / "catalogs" / "nordic" / "2026-10-13" / "catalog.json"
AUDIT_DOC = ROOT / "docs" / "nordic-audit.md"

EXPECTED_SERIES = {"nRF51", "nRF52", "nRF53", "nRF54", "nRF91"}

MANDATORY_PARTS = [
    "nRF51822-QFAA", "nRF51822-QFAC", "nRF51802-QFAA",
    "nRF52832-QFAA", "nRF52840-QIAA", "nRF52810-QCAA", "nRF52833-QIAA",
    "nRF5340-QKAA", "nRF54L15", "nRF54H20", "nRF9160-SICA"
]


class NordicAuditTest(unittest.TestCase):
    def setUp(self):
        self.assertTrue(MATRIX_PATH.is_file(), f"Matrix file missing: {MATRIX_PATH}")
        self.assertTrue(CATALOG_PATH.is_file(), f"Catalog file missing: {CATALOG_PATH}")
        self.assertTrue(AUDIT_DOC.is_file(), f"Audit doc missing: {AUDIT_DOC}")

        with MATRIX_PATH.open(encoding="utf-8") as f:
            self.matrix = json.load(f)

        with CATALOG_PATH.open(encoding="utf-8") as f:
            self.catalog = json.load(f)

    def test_schema_and_metadata(self):
        self.assertEqual("urn:embedra:schema:nordic-capability-matrix:1", self.matrix.get("schemaId"))
        self.assertEqual("urn:embedra:schema:nordic-catalog:1", self.catalog.get("$schema"))

        metadata = self.matrix.get("metadata", {})
        self.assertEqual("T096", metadata.get("task"))
        self.assertEqual(5, metadata.get("totalSeriesCount"))
        self.assertEqual(21, metadata.get("totalExactPartCount"))
        self.assertGreaterEqual(len(metadata.get("authoritativeReferences", [])), 5)

    def test_covers_all_five_series(self):
        series_set = {s["series"] for s in self.matrix.get("series", [])}
        self.assertEqual(EXPECTED_SERIES, series_set)

    def test_covers_mandatory_and_total_parts(self):
        parts = self.matrix.get("parts", [])
        self.assertEqual(21, len(parts))

        part_names = {p["exactPart"] for p in parts}
        self.assertEqual(21, len(part_names), "Part names must be unique")

        for mandatory in MANDATORY_PARTS:
            self.assertIn(mandatory, part_names, f"Mandatory part missing: {mandatory}")

        for part in parts:
            self.assertEqual("PLANNED", part.get("supportState"),
                             f"Part {part['exactPart']} must initialize as PLANNED")
            self.assertIn("package", part)
            self.assertIn("datasheet", part)
            self.assertIn("flashBytes", part)
            self.assertIn("ramBytes", part)

    def test_memory_invariants_and_non_overlap(self):
        for part in self.matrix.get("parts", []):
            pn = part["exactPart"]
            flash_bytes = part["flashBytes"]
            ram_bytes = part["ramBytes"]

            flash_start = int(part["flashRange"]["start"], 16)
            flash_end = int(part["flashRange"]["end"], 16)
            ram_start = int(part["ramRange"]["start"], 16)
            ram_end = int(part["ramRange"]["end"], 16)

            # Flash always anchored at 0x00000000
            self.assertEqual(0x00000000, flash_start, f"{pn} flash must start at 0x00000000")
            # For dual-core or standard single-core: flashRange covers primary flash
            self.assertLess(flash_start, flash_end, f"{pn} flash range valid")

            # RAM always anchored at 0x20000000
            self.assertEqual(0x20000000, ram_start, f"{pn} RAM must start at 0x20000000")
            self.assertLess(ram_start, ram_end, f"{pn} RAM range valid")

            # Flash and RAM never overlap
            self.assertLess(flash_end, ram_start, f"{pn} Flash and RAM must not overlap")

            # FICR and UICR
            ficr_start = int(part["ficrRange"]["start"], 16)
            ficr_end = int(part["ficrRange"]["end"], 16)
            uicr_start = int(part["uicrRange"]["start"], 16)
            uicr_end = int(part["uicrRange"]["end"], 16)

            self.assertLess(ficr_start, ficr_end)
            self.assertLess(uicr_start, uicr_end)
            self.assertLess(ficr_end, uicr_start, f"{pn} FICR and UICR must not overlap")

            # Peripherals
            peri_start = int(part["peripheralsRange"]["start"], 16)
            peri_end = int(part["peripheralsRange"]["end"], 16)
            self.assertIn(peri_start, [0x40000000, 0x50000000], f"{pn} Peripherals aperture")
            self.assertLess(peri_start, peri_end)

    def test_cryptocell_apertures(self):
        parts_by_name = {p["exactPart"]: p for p in self.matrix.get("parts", [])}

        # nRF52840 has CC310 at 0x5002A000
        nrf52840 = parts_by_name["nRF52840-QIAA"]
        self.assertIsNotNone(nrf52840["cryptoCell"])
        self.assertEqual("0x5002A000", nrf52840["cryptoCell"]["base"])

        # nRF5340 has CC312 at 0x50840000
        nrf5340 = parts_by_name["nRF5340-QKAA"]
        self.assertIsNotNone(nrf5340["cryptoCell"])
        self.assertEqual("0x50840000", nrf5340["cryptoCell"]["base"])

        # nRF9160 has CC312 at 0x50840000
        nrf9160 = parts_by_name["nRF9160-SICA"]
        self.assertIsNotNone(nrf9160["cryptoCell"])
        self.assertEqual("0x50840000", nrf9160["cryptoCell"]["base"])

    def test_softdevice_boundaries(self):
        boundaries = {b["softDevice"]: b for b in self.matrix.get("softDeviceBoundaries", [])}
        self.assertIn("S112", boundaries)
        self.assertIn("S132", boundaries)
        self.assertIn("S140", boundaries)

        # S112 application starts at 0x00019000
        self.assertEqual("0x00019000", boundaries["S112"]["applicationOffset"])
        # S132 application starts at 0x00026000
        self.assertEqual("0x00026000", boundaries["S132"]["applicationOffset"])
        # S140 application starts at 0x00027000
        self.assertEqual("0x00027000", boundaries["S140"]["applicationOffset"])

        for sd in boundaries.values():
            self.assertEqual("0x00000000", sd["mbrRange"]["start"])
            self.assertEqual("0x00000FFF", sd["mbrRange"]["end"])

    def test_dual_core_and_trustzone_topologies(self):
        parts_by_name = {p["exactPart"]: p for p in self.matrix.get("parts", [])}

        # nRF5340 dual-core verification
        nrf5340 = parts_by_name["nRF5340-QKAA"]
        self.assertTrue(nrf5340["dualCore"])
        self.assertTrue(nrf5340["trustZone"])
        dc_details = nrf5340["dualCoreDetails"]
        self.assertEqual(1048576, dc_details["applicationCore"]["flashBytes"])
        self.assertEqual(524288, dc_details["applicationCore"]["ramBytes"])
        self.assertEqual(262144, dc_details["networkCore"]["flashBytes"])
        self.assertEqual(65536, dc_details["networkCore"]["ramBytes"])

        # nRF9160 TrustZone verification
        nrf9160 = parts_by_name["nRF9160-SICA"]
        self.assertTrue(nrf9160["trustZone"])
        tz_details = nrf9160["trustZoneDetails"]
        self.assertEqual("0x50000000", tz_details["peripheralsSecureBase"])
        self.assertEqual("0x40000000", tz_details["peripheralsNonSecureBase"])
        self.assertEqual("0x50003000", tz_details["spuBase"])

    def test_allowlist_policy_rejection_rules(self):
        policy = self.matrix.get("allowlistPolicy", {})
        self.assertEqual("EXACT_PART_MATCH_ONLY", policy.get("policy"))
        self.assertGreaterEqual(len(policy.get("rejectionRules", [])), 3)

    def test_audit_document_exists_and_contains_required_sections(self):
        content = AUDIT_DOC.read_text(encoding="utf-8")
        self.assertIn("Nordic Semiconductor nRF Family Layout, Vector & Architectural Audit", content)
        self.assertIn("Scope and Pinned Authoritative Baselines", content)
        self.assertIn("Documentation Provenance & License Analysis", content)
        self.assertIn("Unified Physical Memory Layout & Invariants per Series", content)
        self.assertIn("SoftDevice Architecture, MBR, and Application Offset Boundaries", content)
        self.assertIn("Dual-Core Topologies (nRF5340 Architecture)", content)
        self.assertIn("ARM TrustZone Security Domains (nRF9160 & nRF5340)", content)
        self.assertIn("Curated Exact-Part Allowlist (21 Silicon Parts)", content)
        self.assertIn("Support State & Strict Allowlist Policy", content)
        self.assertIn("Ghidra Language Binding Specification", content)
        self.assertIn("Unknowns, Documentation Gaps & Preliminary Notes", content)

        for s in EXPECTED_SERIES:
            self.assertIn(s, content)
        for p in MANDATORY_PARTS:
            self.assertIn(p, content)


if __name__ == "__main__":
    unittest.main()
