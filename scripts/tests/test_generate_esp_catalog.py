#!/usr/bin/env python3

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "generate-esp-catalog.py"


def load_generator():
    spec = importlib.util.spec_from_file_location("generate_esp_catalog", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class GenerateEspCatalogTest(unittest.TestCase):
    def test_rejects_doctype_and_excessive_nesting(self):
        generator = load_generator()
        with self.assertRaises(generator.SourceError):
            generator.parse_product_page("<!DOCTYPE html><html></html>", "soc", 32)
        nested = "<div>" * 40 + "</div>" * 40
        with self.assertRaises(generator.SourceError):
            generator.parse_product_page(nested, "soc", 32)

    def test_generation_is_deterministic_and_drift_is_exact(self):
        generator = load_generator()
        facts = ROOT / "catalogs" / "espressif" / "sources" / "source-facts.json"
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            generator.generate(facts, Path(first))
            generator.generate(facts, Path(second))
            self.assertEqual(
                (Path(first) / "catalog.json").read_bytes(),
                (Path(second) / "catalog.json").read_bytes())
            current = json.loads((Path(first) / "catalog.json").read_text())
            changed = json.loads(json.dumps(current))
            changed["records"][0]["package"] = "changed"
            drift = generator.diff_catalogs(current, changed)
            self.assertEqual([], drift["added"])
            self.assertEqual([], drift["removed"])
            self.assertEqual([current["records"][0]["recordId"]], drift["changed"])

    def test_parser_retains_all_nested_orderable_part_numbers(self):
        generator = load_generator()
        page = """
        <div class="views-row"><h2>
          <span class="sheet-category-name">ESP32-S3</span>
          <span class="sheet-category-desc">Dual-core 32-bit Xtensa 240 MHz</span>
        </h2><table><tr class="sheet-item">
          <td><span class="sheet-field module-name">ESP32-S3-WROOM-1</span></td>
          <td class="sheet-field module-family">ESP32-S3, ESP32-S3R8</td>
          <td><table><tr class="purchase-item"><td>
            <span class="purchase-pn-text">ESP32-S3-WROOM-1-N8</span>
          </td></tr><tr class="purchase-item"><td>
            <span class="purchase-pn-text">ESP32-S3-WROOM-1-N8R8</span>
          </td></tr></table></td>
        </tr></table></div>
        """
        records = generator.parse_product_page(page, "module", 32)
        self.assertEqual(1, len(records))
        self.assertEqual(
            ["ESP32-S3-WROOM-1-N8", "ESP32-S3-WROOM-1-N8R8"],
            records[0]["purchase-pn-text"])
        self.assertEqual("ESP32-S3", records[0]["series"])

    def test_committed_catalog_matches_regeneration(self):
        generator = load_generator()
        facts = ROOT / "catalogs" / "espressif" / "sources" / "source-facts.json"
        committed = ROOT / "catalogs" / "espressif" / "2026-09-23"
        with tempfile.TemporaryDirectory() as output:
            generator.generate(facts, Path(output))
            self.assertEqual(
                (committed / "catalog.json").read_bytes(),
                (Path(output) / "catalog.json").read_bytes())
            self.assertEqual(
                (committed / "catalog.sha256").read_bytes(),
                (Path(output) / "catalog.sha256").read_bytes())


if __name__ == "__main__":
    unittest.main()
