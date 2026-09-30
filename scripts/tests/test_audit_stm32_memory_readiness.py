"""T039 fail-closed catalog memory-readiness checks."""

import importlib.util
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'scripts' / 'audit-stm32-memory-readiness.py'
SPEC = importlib.util.spec_from_file_location('stm32_memory_audit', SCRIPT)
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)


class MemoryReadinessTest(unittest.TestCase):
    def test_curated_snapshot_reports_actual_gaps(self):
        catalog = ROOT / 'catalogs/stm32/2026-09-29/curated-catalog.json'
        result = AUDIT.audit_catalog(catalog)
        self.assertEqual(53, result['recordCount'])
        self.assertEqual(53, result['missingMemoryBanks'])
        self.assertEqual(11, result['unresolvedFlash'])
        self.assertEqual(0, result['readyCount'])
        self.assertIn('STM32C031C6T3', result['incompleteParts'])

    def test_catalog_fail_closed_when_hash_changes(self):
        catalog = ROOT / 'catalogs/stm32/2026-09-29/curated-catalog.json'
        self.assertEqual(AUDIT.CATALOG_SHA256,
                         AUDIT.sha256(catalog.read_bytes()))
        with self.assertRaises(ValueError):
            AUDIT.audit_bytes(catalog.read_bytes() + b' ')

    def test_no_missing_fact_is_silently_defaulted(self):
        catalog = json.loads((ROOT / 'catalogs/stm32/2026-09-29/'
                              'curated-catalog.json').read_text())
        part = next(record for record in catalog['records']
                    if record['exactPart'] == 'STM32C031C6T3')
        self.assertIn('FLASH_SIZE_UNPAIRED', AUDIT.gaps(part))
        self.assertIn('MEMORY_BANKS_UNKNOWN', AUDIT.gaps(part))
        self.assertNotIn('PROCESSORS_UNKNOWN', AUDIT.gaps(part))


if __name__ == '__main__':
    unittest.main()
