"""Bounded ST source ingestion and snapshot invariants."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'generate-stm32-catalog.py'
spec = importlib.util.spec_from_file_location('stm32_catalog', SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class CatalogTests(unittest.TestCase):
    def make_source(self, xml=None):
        temp = tempfile.TemporaryDirectory()
        path = Path(temp.name)
        (path / 'mcu').mkdir()
        (path / 'mcu' / 'STM32H745XIHx.xml').write_text(xml or '''<Mcu RefName="STM32H745XIHx" Family="STM32H7" Line="STM32H745" Package="TFBGA240"><Core>ARM Cortex-M7</Core><Core>ARM Cortex-M4</Core><Flash>2048</Flash><Ram>864</Ram><Context Core="ARM Cortex-M7" Name="Secure" Secure="true"/><IP Name="AES"/></Mcu>''')
        return temp, path

    def test_topology_and_provenance_are_deterministic(self):
        temp, path = self.make_source()
        try:
            a = module.generate(path)
            b = module.generate(path)
            self.assertEqual(module.canonical(a), module.canonical(b))
            module.validate(a)
            rec = a['records'][0]
            self.assertEqual([n['core'] for n in rec['processors']], ['ARM Cortex-M7', 'ARM Cortex-M4'])
            self.assertEqual(rec['securityEvidence'], ['AES'])
            self.assertEqual(rec['identityKind'], 'ST_REFERENCE_PATTERN')
            self.assertEqual(rec['svdTransformation']['status'], 'UNMAPPED')
        finally:
            temp.cleanup()

    def test_cancelled_before_parse(self):
        temp, path = self.make_source()
        try:
            with self.assertRaisesRegex(module.CatalogError, 'cancelled'):
                module.generate(path, cancelled=lambda: True)
        finally:
            temp.cleanup()

    def test_dtd_and_entities_rejected(self):
        temp, path = self.make_source('<!DOCTYPE Mcu [<!ENTITY a "b">]><Mcu/>')
        try:
            with self.assertRaisesRegex(module.CatalogError, 'DTD/entity'):
                module.generate(path)
        finally:
            temp.cleanup()

    def test_malformed_and_oversized_rejected(self):
        temp, path = self.make_source('<Mcu>')
        try:
            with self.assertRaisesRegex(module.CatalogError, 'malformed XML'):
                module.generate(path)
            (path / 'mcu' / 'STM32H745XIHx.xml').write_bytes(b'x' * (module.MAX_FILE_BYTES + 1))
            with self.assertRaisesRegex(module.CatalogError, 'oversized'):
                module.generate(path)
        finally:
            temp.cleanup()

    def test_path_identity_and_duplicate_rejected(self):
        temp, path = self.make_source()
        try:
            (path / 'mcu' / 'STM32H745XIGx.xml').write_bytes((path / 'mcu' / 'STM32H745XIHx.xml').read_bytes())
            with self.assertRaisesRegex(module.CatalogError, 'RefName'):
                module.generate(path)
        finally:
            temp.cleanup()

    def test_snapshot_coverage(self):
        snapshot = SCRIPT.parents[1] / 'catalogs/stm32/2026-09-28/source-catalog.json'
        catalog = json.loads(snapshot.read_bytes())
        module.validate(catalog)
        self.assertEqual(len(catalog['records']), 2240)
        self.assertTrue(any(r['family'] == 'STM32MP2' for r in catalog['records']))
        self.assertTrue(any(len(r['processors']) == 2 for r in catalog['records']))
        self.assertEqual(module.digest(snapshot.read_bytes()),
                         (snapshot.parent / 'source-catalog.sha256').read_text().strip())


if __name__ == '__main__':
    unittest.main()
