import json
import os
import unittest
import hashlib

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
MATRIX_PATH = os.path.join(PROJECT_ROOT, ".embedra/evidence/tasks/T080-capability-matrix.json")
FIXTURE_BASE = os.path.join(PROJECT_ROOT, "src/test/resources/fixtures")
ORACLE_BASE = os.path.join(PROJECT_ROOT, "src/test/resources/oracles")

class EspFullFlashFixturesTest(unittest.TestCase):
    def setUp(self):
        with open(MATRIX_PATH, "r", encoding="utf-8") as f:
            self.matrix = json.load(f)

    def test_all_14_series_have_fixtures_and_oracles(self):
        series_list = self.matrix["series"]
        self.assertEqual(len(series_list), 14)

        for s in series_list:
            target_slug = s["series"].lower().replace("-", "")
            fixture_dir = os.path.join(FIXTURE_BASE, target_slug, "full-flash")
            oracle_dir = os.path.join(ORACLE_BASE, target_slug, "full-flash")

            self.assertTrue(os.path.isdir(fixture_dir), f"Missing fixture dir: {fixture_dir}")
            self.assertTrue(os.path.isdir(oracle_dir), f"Missing oracle dir: {oracle_dir}")

            # Verify standard fixtures
            for name in ["default-factory", "custom-offset-misleading-magic", "ota-custom-encrypted", "invalid-partition-md5"]:
                bin_path = os.path.join(fixture_dir, f"{name}.bin")
                manifest_path = os.path.join(fixture_dir, f"{name}.bin.manifest.json")
                exp_path = os.path.join(oracle_dir, f"{name}.expectations.json")

                self.assertTrue(os.path.isfile(bin_path), f"Missing {bin_path}")
                self.assertTrue(os.path.isfile(manifest_path), f"Missing {manifest_path}")
                self.assertTrue(os.path.isfile(exp_path), f"Missing {exp_path}")

                with open(bin_path, "rb") as bf:
                    data = bf.read()
                with open(manifest_path, "r", encoding="utf-8") as mf:
                    manifest = json.load(mf)
                with open(exp_path, "r", encoding="utf-8") as ef:
                    exp = json.load(ef)

                actual_sha = hashlib.sha256(data).hexdigest()
                self.assertEqual(manifest["sha256"], actual_sha, f"SHA mismatch on {manifest_path}")
                self.assertEqual(manifest["redistributionStatus"], "REDISTRIBUTABLE")
                self.assertIn("REDISTRIBUTABLE", manifest["redistributionStatus"])

            if target_slug != "esp32s3":
                # Check additional T081 fixtures for promoted series
                for name in ["malformed-wrong-chip", "malformed-truncated", "erased-slot", "malformed-overlapping-partitions"]:
                    bin_path = os.path.join(fixture_dir, f"{name}.bin")
                    manifest_path = os.path.join(fixture_dir, f"{name}.bin.manifest.json")
                    exp_path = os.path.join(oracle_dir, f"{name}.expectations.json")
                    self.assertTrue(os.path.isfile(bin_path), f"Missing {bin_path}")
                    self.assertTrue(os.path.isfile(manifest_path), f"Missing {manifest_path}")
                    self.assertTrue(os.path.isfile(exp_path), f"Missing {exp_path}")

    def test_bootloader_offset_invariants(self):
        for s in self.matrix["series"]:
            target_slug = s["series"].lower().replace("-", "")
            bin_path = os.path.join(FIXTURE_BASE, target_slug, "full-flash/default-factory.bin")
            with open(bin_path, "rb") as f:
                data = f.read()

            if target_slug == "esp32":
                # Bootloader at 0x1000
                self.assertEqual(data[0x1000], 0xe9, "ESP32 bootloader magic must be at 0x1000")
                # 0x0000..0x1000 should be 0xFF erased flash
                self.assertEqual(set(data[0:0x1000]), {0xff}, "ESP32 pre-bootloader region must be erased (0xFF)")
            else:
                # Bootloader at 0x0000
                self.assertEqual(data[0x0000], 0xe9, f"{target_slug} bootloader magic must be at 0x0000")

            # Partition table at 0x8000
            self.assertEqual(data[0x8000], 0xaa)
            self.assertEqual(data[0x8001], 0x50)

if __name__ == "__main__":
    unittest.main()
