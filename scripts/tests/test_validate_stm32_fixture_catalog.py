"""T033 exact-part fixture and catalog boundary checks."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / 'validate-stm32-fixture-catalog.py'
spec = importlib.util.spec_from_file_location('stm32_fixture_catalog', SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class FixtureCatalogTests(unittest.TestCase):
    def records(self):
        return json.loads(module.CATALOG.read_text())['records']

    def test_all_selected_records_are_structurally_valid(self):
        records = self.records()
        self.assertEqual(53, len(records))
        self.assertEqual(53, module.validate_records(records))

    def test_duplicate_identity_and_unsupported_promotion_rejected(self):
        records = self.records()
        with self.assertRaises(module.ValidationError):
            module.validate_records(records + [records[0]])
        records[0]['supportState'] = 'VERIFIED'
        with self.assertRaises(module.ValidationError):
            module.validate_records(records)

    def test_ambiguous_memory_and_irq_must_stay_explicit(self):
        records = self.records()
        ambiguous = next(r for r in records if r['flashStatus'] == 'SOURCE_UNPAIRED')
        ambiguous['flashKiB'] = ambiguous['flashKiBCandidates'][0]
        with self.assertRaises(module.ValidationError):
            module.validate_records(records)
        records = self.records()
        ambiguous = next(r for r in records if r['interruptStatus'] != 'MAPPED_SINGLE')
        ambiguous['interruptStatus'] = 'MAPPED_SINGLE'
        with self.assertRaises(module.ValidationError):
            module.validate_records(records)

    def test_bad_processor_and_irq_shape_rejected(self):
        records = self.records()
        records[0]['processors'][0]['index'] = -1
        with self.assertRaises(module.ValidationError):
            module.validate_records(records)
        records = self.records()
        records[0]['interrupts'].append(records[0]['interrupts'][0].copy())
        with self.assertRaises(module.ValidationError):
            module.validate_records(records)

    def test_fixture_set_is_exact_and_digest_bound(self):
        self.assertEqual(3, module.validate_fixture_set())
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)
            for file in module.FIXTURE_DIR.iterdir():
                if file.is_file():
                    (path / file.name).write_bytes(file.read_bytes())
            fixture = path / 'STM32F103C8T6.bin'
            fixture.write_bytes(fixture.read_bytes() + b'\x00')
            with self.assertRaises(module.ValidationError):
                module.validate_fixture_set(fixture_dir=path)

    def test_cortex_m0_plus_fixture_is_addressed_and_bound_to_c051(self):
        self.assertEqual(3, module.validate_c0_fixture_set())
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)
            for file in module.C0_FIXTURE_DIR.iterdir():
                if file.is_file():
                    (path / file.name).write_bytes(file.read_bytes())
            fixture = path / 'STM32C071RBT6.hex'
            fixture.write_bytes(fixture.read_bytes().replace(b'0800', b'0801', 1))
            with self.assertRaises(module.ValidationError):
                module.validate_c0_fixture_set(fixture_dir=path)

    def test_cross_family_samples_use_sourced_addresses(self):
        self.assertEqual(18, module.validate_core_samples())
        n6 = json.loads((module.CORE_ORACLE_DIR / 'STM32N657X0H3Q.json').read_text())
        self.assertEqual('RAM_VECTOR_SAMPLE', n6['imageSemantics'])
        self.assertEqual('0x34000000', n6['imageBase'])
        self.assertEqual('0x34000101', n6['resetVector'])
        wl3 = json.loads((module.CORE_ORACLE_DIR / 'STM32WL33CCV6TR.json').read_text())
        self.assertEqual('0x10040000', wl3['imageBase'])
        self.assertEqual('0x10040101', wl3['resetVector'])
        f2 = json.loads((module.CORE_ORACLE_DIR / 'STM32F207ZGT6.json').read_text())
        self.assertIsNone(f2['flashKiB'])
        self.assertEqual('RAM_VECTOR_SAMPLE', f2['imageSemantics'])

    def test_all_selected_family_labels_have_a_golden(self):
        catalog = self.records()
        sampled = set(module.F103) | set(module.C0_PARTS) | set(module.CORE_PARTS)
        by_part = {record['exactPart']: record for record in catalog}
        self.assertEqual({record['family'] for record in catalog},
                         {by_part[part]['family'] for part in sampled})


if __name__ == '__main__':
    unittest.main()
