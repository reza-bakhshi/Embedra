"""Exact STM32 SVD applicability contracts."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'scripts' / 'generate-stm32-svd-applicability.py'
SPEC = importlib.util.spec_from_file_location('stm32_svd_applicability', SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

CURATED = ROOT / 'catalogs/stm32/2026-09-29/curated-catalog.json'
RULES = ROOT / 'catalogs/stm32/2026-09-28/svd-rules.json'
OUTPUT = ROOT / 'catalogs/stm32/2026-09-29/svd-applicability.json'


class ApplicabilityTests(unittest.TestCase):
    def test_committed_snapshot_regenerates_and_matches_digest(self):
        generated = MODULE.canonical(MODULE.generate(CURATED, RULES))
        self.assertEqual(OUTPUT.read_bytes(), generated)
        self.assertEqual(MODULE.sha(generated),
                         (OUTPUT.parent / 'svd-applicability.sha256').read_text().strip())

    def test_selection_is_exact_and_never_wildcard(self):
        data = json.loads(OUTPUT.read_bytes())
        self.assertEqual(MODULE.SELECTION_RULE, data['selectionRule'])
        statuses = {}
        for part in data['parts']:
            statuses[part['status']] = statuses.get(part['status'], 0) + 1
            for entry in part['svdFiles']:
                self.assertNotIn('X', entry['deviceName'])
                self.assertEqual(entry['deviceName'], entry['deviceName'].upper())
            if part['status'] == 'UNAVAILABLE':
                self.assertEqual([], part['svdFiles'])
                self.assertTrue(part['reason'])
        self.assertEqual(8, statuses['UNAVAILABLE'])
        self.assertEqual(8, statuses['EXACT_SVD_SHIPPED'])
        self.assertEqual(37, statuses['EXACT_SVD_DEFERRED'])
        self.assertEqual(53, sum(statuses.values()))

    def test_wildcard_device_names_are_not_applicable(self):
        self.assertFalse(MODULE.exact_prefix('STM32U5G9ZJT6Q', 'STM32U5Gx'))
        self.assertFalse(MODULE.exact_prefix('STM32H735IGK6', 'STM32H73x'))
        self.assertTrue(MODULE.exact_prefix('STM32F103C8T6', 'STM32F103'))
        self.assertFalse(MODULE.exact_prefix('STM32F103C8T6', 'STM32F107'))

    def test_tampered_or_wrong_source_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            curated = Path(folder) / 'curated.json'
            curated.write_bytes(CURATED.read_bytes().replace(b'PLANNED', b'VERIFIED', 1))
            with self.assertRaisesRegex(MODULE.ApplicabilityError, 'curated catalog'):
                MODULE.generate(curated, RULES)

    def test_no_family_or_neighbour_line_is_promoted(self):
        data = json.loads(OUTPUT.read_bytes())
        by_part = {part['exactPart']: part for part in data['parts']}
        self.assertEqual('UNAVAILABLE', by_part['STM32F207ZGT6']['status'])
        self.assertEqual('UNAVAILABLE', by_part['STM32U5G9ZJT6Q']['status'])
        self.assertEqual(['STM32WB55_CM4', 'STM32WB55_CM0P'],
                         [entry['deviceName']
                          for entry in by_part['STM32WB55RGV6']['svdFiles']])


if __name__ == '__main__':
    unittest.main()
