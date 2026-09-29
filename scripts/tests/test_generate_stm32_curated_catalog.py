"""Curated STM32 acceptance and exact-identity regressions."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'generate-stm32-curated-catalog.py'
spec = importlib.util.spec_from_file_location('stm32_curated', SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class CuratedTests(unittest.TestCase):
    def selection(self, folder, change):
        data = json.loads(module.SELECTION.read_text())
        change(data['parts'])
        path = Path(folder) / 'selection.json'
        path.write_text(json.dumps(data))
        return path

    def test_selected_snapshot_and_distinct_variants(self):
        data = module.canonical(module.generate())
        self.assertEqual(data, module.OUTPUT.read_bytes())
        self.assertEqual(module.sha(data), module.OUTPUT.with_suffix('.sha256').read_text().strip())
        parts = json.loads(data)['records']
        self.assertEqual(len(parts), 53)
        self.assertGreaterEqual(len({p['family'] for p in parts}), 19)
        f103 = [p for p in parts if p['exactPart'].startswith('STM32F103')]
        self.assertEqual([p['exactPart'] for p in f103],
                         ['STM32F103C8T6', 'STM32F103CBT6', 'STM32F103RBT6'])
        self.assertEqual([(p['package'], p['flashKiB'], p['ramKiB']) for p in f103],
                         [('LQFP48', 64, 20), ('LQFP48', 128, 20), ('LQFP64', 128, 20)])
        self.assertTrue(all(len(p['interrupts']) == 52 for p in f103))
        self.assertTrue(all(p['lifecycle'] == 'UNKNOWN' and p['deviceIdStatus'] == 'UNKNOWN'
                            and p['svdTransformation']['status'] == 'UNMAPPED'
                            and p['supportState'] == 'PLANNED' for p in parts))
        self.assertTrue(all(p['memoryBanksStatus'] == 'UNKNOWN'
                            and p['peripheralStatus'] == 'REFERENCE_PATTERN_SCOPE'
                            and p['revisionStatus'] == 'UNKNOWN' for p in parts))

    def test_family_wildcard_and_unreviewed_suffix_rejected(self):
        for value in ('STM32F103', 'STM32F103C8Tx', 'STM32F103C8T7',
                      'STM32WB5MMGH6TR'):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as folder:
                path = self.selection(folder, lambda parts: parts[0].update(exactPart=value))
                with self.assertRaises(module.CuratedError):
                    module.generate(selection=path)

    def test_memory_and_package_mismatch_rejected(self):
        for field, value in [('flashKiB', 128), ('package', 'LQFP64'),
                             ('reference', 'STM32F103R(8-B)Tx')]:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as folder:
                path = self.selection(folder, lambda parts: next(p for p in parts if p['exactPart'] == 'STM32F103C8T6').update({field: value}))
                with self.assertRaises(module.CuratedError):
                    module.generate(selection=path)

    def test_board_part_source_and_market_guard(self):
        for field, value in [('reference', 'STM32F103C(8-B)Tx'),
                             ('marketUrl', 'https://example.org/part'),
                             ('marketingStatus', 'UNKNOWN')]:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as folder:
                path = self.selection(folder, lambda parts: parts[0].update({field: value}))
                with self.assertRaises(module.CuratedError):
                    module.generate(selection=path)

    def test_duplicate_and_unsafe_input_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = self.selection(folder, lambda parts: parts.append(parts[-1].copy()))
            with self.assertRaisesRegex(module.CuratedError, 'sorted and unique'):
                module.generate(selection=path)
            path.write_text('x' * (module.MAX_BYTES + 1))
            with self.assertRaisesRegex(module.CuratedError, 'oversized'):
                module.generate(selection=path)

    def test_cmsis_source_binding_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            data = json.loads(module.CMSIS.read_text())
            data['sourceCatalogSha256'] = '0' * 64
            path = Path(folder) / 'cmsis.json'
            path.write_text(json.dumps(data))
            with self.assertRaisesRegex(module.CuratedError, 'provenance'):
                module.generate(cmsis=path)

if __name__ == '__main__':
    unittest.main()
