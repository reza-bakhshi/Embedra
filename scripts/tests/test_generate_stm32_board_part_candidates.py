"""Board CPN reconciliation retains uncertain facts and source provenance."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'generate-stm32-board-part-candidates.py'
spec = importlib.util.spec_from_file_location('stm32_board_candidates', SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class CandidateTests(unittest.TestCase):
    def test_snapshot_integrity_and_unpaired_memory(self):
        data = module.canonical(module.generate())
        self.assertEqual(data, module.OUTPUT.read_bytes())
        self.assertEqual(module.sha(data), module.OUTPUT.with_suffix('.sha256').read_text().strip())
        rows = json.loads(data)['records']
        self.assertEqual(len(rows), 89)
        self.assertEqual(sum(x['flashPairingStatus'] == 'UNPAIRED_ALTERNATIVES' for x in rows), 14)
        self.assertEqual(sum(x['familyReconciliation'] == 'ALIAS_REVIEW' for x in rows), 3)
        self.assertTrue(all(x['marketStatus'] == 'NOT_REVIEWED' and
                            x['deviceIdStatus'] == 'UNKNOWN' and
                            x['svdStatus'] == 'EXACT_APPLICABILITY_UNVERIFIED'
                            for x in rows))

    def test_cmsis_binding_and_license_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            value = json.loads(module.CMSIS.read_text())
            value['sourceCatalogSha256'] = '0' * 64
            path = Path(folder) / 'cmsis.json'; path.write_text(json.dumps(value))
            with self.assertRaisesRegex(module.CandidateError, 'CMSIS source/license'):
                module.generate(cmsis_path=path)
            value['sourceCatalogSha256'] = module.sha(module.PIN.read_bytes())
            value['repositories'][0]['license'] = 'restricted'
            path.write_text(json.dumps(value))
            with self.assertRaisesRegex(module.CandidateError, 'CMSIS source/license'):
                module.generate(cmsis_path=path)

    def test_wildcard_cpn_not_promoted(self):
        with tempfile.TemporaryDirectory() as folder:
            value = json.loads(module.BOARD.read_text())
            row = next(x for x in value['records'] if x['cpnStatus'] == 'NONEXACT_CPN')
            self.assertIsNone(row['exactPart'])
            row['exactPart'] = 'STM32U3C5ZITxQ'
            path = Path(folder) / 'board.json'; path.write_text(json.dumps(value))
            with self.assertRaisesRegex(module.CandidateError, 'nonexact board CPN'):
                module.generate(board_path=path)

if __name__ == '__main__':
    unittest.main()
