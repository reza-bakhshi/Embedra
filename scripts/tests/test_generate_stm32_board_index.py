"""ST board-source extraction contracts and pinned snapshot integrity."""
import importlib.util
import json
from pathlib import Path
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'generate-stm32-board-index.py'
spec = importlib.util.spec_from_file_location('stm32_board_index', SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
SNAPSHOT = SCRIPT.parents[1] / 'catalogs/stm32/sources/board-index.json'

class BoardIndexTests(unittest.TestCase):
    def test_exact_cpn_and_reference_are_separate(self):
        path = Path('A10_Nucleo_NUCLEO-F103RB_STM32F103RB_Board_AllConfig.ioc')
        data = b'Mcu.CPN=STM32F103RBT6\nMcu.Name=STM32F103R(8-B)Tx\nMcu.Family=STM32F1\nMcu.Package=LQFP64\nboard=NUCLEO-F103RB\n'
        row = module.parse(data, path)
        self.assertEqual(row['exactPart'], 'STM32F103RBT6')
        self.assertEqual(row['reference'], 'STM32F103R(8-B)Tx')
        self.assertEqual(row['cpnStatus'], 'EXACT')
        self.assertEqual(row['category'], 'Nucleo')
        self.assertEqual(row['sourceSha256'], module.sha(data))

    def test_absent_and_nonexact_cpn_stay_unresolved(self):
        base = b'Mcu.Name=STM32U3C5ZIxQ\nMcu.Family=STM32U3\nMcu.Package=LQFP144\n'
        path = Path('B61_Nucleo_NUCLEO-U3C5ZI-Q_STM32U3C5ZIxQ_Board_AllConfig.ioc')
        self.assertEqual(module.parse(base, path)['cpnStatus'], 'REFERENCE_ONLY')
        row = module.parse(base + b'Mcu.CPN=STM32U3C5ZITxQ\n', path)
        self.assertEqual(row['cpnStatus'], 'NONEXACT_CPN')
        self.assertIsNone(row['exactPart'])

    def test_malformed_duplicate_and_missing_identity_rejected(self):
        path = Path('test_Nucleo_BOARD_STM32X.ioc')
        for data in (b'Mcu.Name=STM32F103RBT6\n',
                     b'Mcu.Name=STM32F103RBT6\nMcu.Name=STM32F103RBT6\n',
                     b'Mcu.Name STM32F103RBT6\n'):
            with self.subTest(data=data), self.assertRaises(module.BoardError):
                module.parse(data, path)

    def test_pinned_snapshot_counts_and_digest(self):
        raw = SNAPSHOT.read_bytes()
        self.assertEqual(module.sha(raw), SNAPSHOT.with_suffix('.sha256').read_text().strip())
        rows = json.loads(raw)['records']
        self.assertEqual(len(rows), 277)
        self.assertEqual(sum(x['cpnStatus'] == 'EXACT' for x in rows), 148)
        self.assertEqual(len({x['exactPart'] for x in rows if x['exactPart']}), 89)
        self.assertEqual(sum(x['category'] == 'Nucleo' for x in rows), 127)
        self.assertEqual(sum(x['category'] == 'Discovery' for x in rows), 85)

if __name__ == '__main__':
    unittest.main()
