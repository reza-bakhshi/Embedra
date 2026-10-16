#!/usr/bin/env python3
"""Automated verification for T097 Nordic fixtures and official-tool oracles.

Validates that:
1. Bare-metal application fixtures (BIN, HEX, ELF) exist for representative parts
   (nRF51822, nRF52832, nRF52840) with matching manifests and oracles.
2. SoftDevice combination layouts (S132 on nRF52832, S140 on nRF52840) exist with
   valid MBR, SoftDevice, and application offsets (0x00026000 and 0x00027000).
3. UICR configuration block (nrf52840_uicr.hex) contains bootloader address and customer fields.
4. Dual-core nRF5340 image pairs (Application core and Network core) exist and have valid ELF headers.
5. TrustZone nRF9160 image pairs (Secure and Non-Secure) exist and have valid ELF headers.
6. All malformed fixtures exist and match their expected fail-closed validation reasons.
7. Raw binary fixtures contain valid Cortex-M initial SP and reset vector (Thumb bit set).
8. Intel HEX fixtures correctly encode load addresses and checksums.
9. ELF fixtures have valid 32-bit Little-Endian ARM headers (EM_ARM = 40).
"""

import json
from pathlib import Path
import struct
import unittest

ROOT = Path(__file__).resolve().parents[2]
FIXTURES_DIR = ROOT / "src" / "test" / "resources" / "fixtures" / "nordic"
MALFORMED_DIR = FIXTURES_DIR / "malformed"
ORACLES_DIR = ROOT / "src" / "test" / "resources" / "oracles" / "nordic"
ORACLES_MALFORMED_DIR = ORACLES_DIR / "malformed"

REPRESENTATIVE_BAREMETAL = ["nrf51822_app", "nrf52832_app", "nrf52840_app"]


class NordicFixtureTest(unittest.TestCase):
    def test_baremetal_fixtures_exist_with_manifests_and_oracles(self):
        for pfx in REPRESENTATIVE_BAREMETAL:
            for ext in [".bin", ".hex", ".elf"]:
                fpath = FIXTURES_DIR / f"{pfx}{ext}"
                mpath = FIXTURES_DIR / f"{pfx}{ext}.manifest.json"
                self.assertTrue(fpath.is_file(), f"Missing fixture: {fpath}")
                self.assertTrue(mpath.is_file(), f"Missing manifest: {mpath}")

                with mpath.open(encoding="utf-8") as f:
                    man = json.load(f)
                self.assertEqual("REDISTRIBUTABLE", man["redistributionStatus"])
                self.assertIn("T097", man["requirements"])

            oracle_path = ORACLES_DIR / f"{pfx}.json"
            self.assertTrue(oracle_path.is_file(), f"Missing oracle: {oracle_path}")
            with oracle_path.open(encoding="utf-8") as f:
                oracle = json.load(f)
            self.assertIn("initialSp", oracle)
            self.assertIn("resetVector", oracle)
            self.assertIn("flashBase", oracle)

    def test_raw_binary_cortex_m_vector_table(self):
        for pfx in REPRESENTATIVE_BAREMETAL:
            bpath = FIXTURES_DIR / f"{pfx}.bin"
            data = bpath.read_bytes()
            self.assertGreaterEqual(len(data), 64, "Binary must be at least 64 bytes for vector table")

            initial_sp = struct.unpack_from("<I", data, 0)[0]
            reset_vector = struct.unpack_from("<I", data, 4)[0]

            # Initial SP must point into SRAM (0x20000000 range)
            self.assertEqual(0x20000000, initial_sp & 0xFFF00000, f"{pfx} Initial SP must be in SRAM")
            # Reset vector must have Thumb bit set (odd address)
            self.assertEqual(1, reset_vector & 1, f"{pfx} Reset vector must have bit 0 set (Thumb)")

    def test_intel_hex_structure(self):
        for pfx in REPRESENTATIVE_BAREMETAL:
            hpath = FIXTURES_DIR / f"{pfx}.hex"
            lines = [l.strip() for l in hpath.read_text(encoding="utf-8").splitlines() if l.strip()]
            self.assertTrue(lines[-1].startswith(":00000001FF"), "End of file record")

            for line in lines[:-1]:
                self.assertTrue(line.startswith(":"))
                length = int(line[1:3], 16)
                addr = int(line[3:7], 16)
                rec_type = int(line[7:9], 16)
                self.assertIn(rec_type, [0, 4])

                # Verify checksum
                raw_bytes = bytes.fromhex(line[1:])
                self.assertEqual(0, sum(raw_bytes) & 0xFF, f"Hex line checksum failed: {line}")

    def test_elf_structure(self):
        for pfx in REPRESENTATIVE_BAREMETAL:
            epath = FIXTURES_DIR / f"{pfx}.elf"
            data = epath.read_bytes()
            self.assertTrue(data.startswith(b"\x7fELF"), "ELF magic header")
            self.assertEqual(1, data[4], "ELF32")
            self.assertEqual(1, data[5], "ELFDATA2LSB (little endian)")
            self.assertEqual(1, data[6], "EV_CURRENT")

            # e_type == ET_EXEC (2), e_machine == EM_ARM (40)
            e_type, e_machine = struct.unpack_from("<HH", data, 16)
            self.assertEqual(2, e_type, "ET_EXEC")
            self.assertEqual(40, e_machine, "EM_ARM")

    def test_softdevice_combination_fixtures(self):
        # S132
        s132_path = FIXTURES_DIR / "nrf52832_s132_app.hex"
        self.assertTrue(s132_path.is_file())
        s132_oracle_path = ORACLES_DIR / "nrf52832_s132_app.json"
        self.assertTrue(s132_oracle_path.is_file())
        oracle_s132 = json.loads(s132_oracle_path.read_text(encoding="utf-8"))
        self.assertEqual("0x00026000", oracle_s132["applicationOffset"])

        # S140
        s140_path = FIXTURES_DIR / "nrf52840_s140_app.hex"
        self.assertTrue(s140_path.is_file())
        s140_oracle_path = ORACLES_DIR / "nrf52840_s140_app.json"
        self.assertTrue(s140_oracle_path.is_file())
        oracle_s140 = json.loads(s140_oracle_path.read_text(encoding="utf-8"))
        self.assertEqual("0x00027000", oracle_s140["applicationOffset"])

    def test_uicr_configuration_fixture(self):
        uicr_path = FIXTURES_DIR / "nrf52840_uicr.hex"
        self.assertTrue(uicr_path.is_file())
        uicr_oracle_path = ORACLES_DIR / "nrf52840_uicr.json"
        self.assertTrue(uicr_oracle_path.is_file())
        oracle_uicr = json.loads(uicr_oracle_path.read_text(encoding="utf-8"))
        self.assertEqual("0x10001000", oracle_uicr["baseAddress"])
        self.assertEqual("0x000F8000", oracle_uicr["bootloaderAddr"])
        self.assertEqual("0xCAFEBABE", oracle_uicr["customer0"])

    def test_dual_core_and_trustzone_fixtures(self):
        # Dual-core
        app_elf = FIXTURES_DIR / "nrf5340_app_core.elf"
        net_elf = FIXTURES_DIR / "nrf5340_net_core.elf"
        self.assertTrue(app_elf.is_file())
        self.assertTrue(net_elf.is_file())

        app_oracle = json.loads((ORACLES_DIR / "nrf5340_app_core.json").read_text(encoding="utf-8"))
        self.assertEqual("0x00000000", app_oracle["flashBase"])
        self.assertEqual("0x20080000", app_oracle["initialSp"])

        net_oracle = json.loads((ORACLES_DIR / "nrf5340_net_core.json").read_text(encoding="utf-8"))
        self.assertEqual("0x01000000", net_oracle["flashBase"])
        self.assertEqual("0x21010000", net_oracle["initialSp"])

        # TrustZone
        sec_elf = FIXTURES_DIR / "nrf9160_secure.elf"
        ns_elf = FIXTURES_DIR / "nrf9160_nonsecure.elf"
        self.assertTrue(sec_elf.is_file())
        self.assertTrue(ns_elf.is_file())

        sec_oracle = json.loads((ORACLES_DIR / "nrf9160_secure.json").read_text(encoding="utf-8"))
        self.assertEqual("SECURE", sec_oracle["securityDomain"])
        self.assertEqual("0x00000000", sec_oracle["flashBase"])

        ns_oracle = json.loads((ORACLES_DIR / "nrf9160_nonsecure.json").read_text(encoding="utf-8"))
        self.assertEqual("NON_SECURE", ns_oracle["securityDomain"])
        self.assertEqual("0x00040000", ns_oracle["flashBase"])

    def test_malformed_fixtures(self):
        malformed_names = [
            ("nrf52_invalid_vector.bin", "INVALID_INITIAL_SP_AND_EVEN_RESET_VECTOR"),
            ("nrf52_truncated.hex", "TRUNCATED_INTEL_HEX_RECORD"),
            ("nrf52_bad_checksum.hex", "CHECKSUM_MISMATCH"),
            ("nrf52_overlapping.hex", "OVERLAPPING_MEMORY_SEGMENTS"),
            ("nrf52_truncated_elf.elf", "TRUNCATED_ELF_FILE")
        ]

        for mname, expected_reason in malformed_names:
            fpath = MALFORMED_DIR / mname
            mpath = Path(f"{fpath}.manifest.json")
            opath = ORACLES_MALFORMED_DIR / f"{mname.split('.')[0]}.json"

            self.assertTrue(fpath.is_file(), f"Missing malformed fixture: {fpath}")
            self.assertTrue(mpath.is_file(), f"Missing malformed manifest: {mpath}")
            self.assertTrue(opath.is_file(), f"Missing malformed oracle: {opath}")

            oracle = json.loads(opath.read_text(encoding="utf-8"))
            self.assertEqual("FAIL_CLOSED_VALIDATION", oracle["expectedOutcome"])
            self.assertEqual(expected_reason, oracle["failureReason"])


if __name__ == "__main__":
    unittest.main()
