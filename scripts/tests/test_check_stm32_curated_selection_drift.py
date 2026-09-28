"""Curated STM32 network drift predicate contracts."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'check-stm32-curated-selection-drift.py'
spec = importlib.util.spec_from_file_location('stm32_drift', SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class DriftTests(unittest.TestCase):
    def test_current_pinned_evidence_passes(self):
        # Offline synthetic equivalents keep this test independent of host clones.
        with tempfile.TemporaryDirectory() as folder:
            a = Path(folder) / 'arduino'; c = Path(folder) / 'cube'
            a.write_text('STM32F103C8T6-Blue-Pill STM32F103CB')
            c.write_text('STM32F103RBT6')
            self.assertEqual(module.check(a, c)['status'], 'PASS')
            a.write_text('STM32F103C8T6-Blue-Pill')
            self.assertEqual(module.check(a, c)['status'], 'REVIEW_REQUIRED')

    def test_oversized_input_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder) / 'input'; p.write_text('x' * (module.MAX_BYTES + 1))
            with self.assertRaisesRegex(module.DriftError, 'oversized'):
                module.bounded(p)

if __name__ == '__main__':
    unittest.main()
