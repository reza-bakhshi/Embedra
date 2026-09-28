"""ST CMSIS IRQ extraction and reference matching invariants."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'generate-stm32-cmsis-interrupts.py'
spec = importlib.util.spec_from_file_location('stm32_cmsis', SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class CmsisTests(unittest.TestCase):
    def test_reference_alternatives_and_header_matching(self):
        self.assertEqual(module.alternatives('STM32F103V(C-D-E)Tx'),
                         ['STM32F103VCTx', 'STM32F103VDTx', 'STM32F103VETx'])
        self.assertTrue(module.matches('STM32F103V(C-D-E)Tx', 'stm32f103xe'))
        self.assertFalse(module.matches('STM32F103V(C-D-E)Tx', 'stm32f103xg'))
        self.assertTrue(module.matches('STM32MP257FALx', 'stm32mp257fxx_cm33'))

    def test_unbounded_alternatives_rejected(self):
        with self.assertRaises(module.CmsisError):
            module.alternatives('STM32F103V(' + '-'.join('A' for _ in range(17)) + ')Tx')

    def test_irq_extraction_core_and_conditional_status(self):
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder) / 'stm32mp257fxx_cm33.h'
            p.write_text('typedef enum { Reset_IRQn = -15, GPIO_IRQn = 7, } IRQn_Type;')
            parsed = module.parse_irq(p)
            self.assertEqual(parsed['core'], 'CM33')
            self.assertEqual(parsed['interrupts'], [{'name':'Reset_IRQn','number':-15},
                                                     {'name':'GPIO_IRQn','number':7}])
            self.assertFalse(parsed['conditional'])
            p.write_text('typedef enum {\n#if FLAG\nGPIO_IRQn = 7,\n#endif\n} IRQn_Type;')
            self.assertTrue(module.parse_irq(p)['conditional'])

    def test_conflicting_irq_and_size_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder) / 'stm32h745xx.h'
            p.write_text('typedef enum { GPIO_IRQn = 7, GPIO_IRQn = 8, } IRQn_Type;')
            with self.assertRaisesRegex(module.CmsisError, 'duplicate'):
                module.parse_irq(p)
            p.write_bytes(b'x' * (module.MAX_HEADER_BYTES + 1))
            with self.assertRaisesRegex(module.CmsisError, 'oversized'):
                module.parse_irq(p)

    def test_snapshot_integrity_and_coverage(self):
        path = SCRIPT.parents[1] / 'catalogs/stm32/2026-09-28/cmsis-interrupts.json'
        data = path.read_bytes()
        import json
        catalog = json.loads(data)
        self.assertEqual(module.sha(data), (path.parent / 'cmsis-interrupts.sha256').read_text().strip())
        self.assertEqual(len(catalog['repositories']), 27)
        self.assertEqual(len(catalog['mappings']), 2240)
        self.assertEqual(len(catalog['headers']), 377)
        self.assertTrue(any(m['status'] == 'UNRESOLVED' for m in catalog['mappings']))
        mp = next(m for m in catalog['mappings'] if m['reference'] == 'STM32MP257FALx')
        self.assertEqual({catalog['headers'][h]['core'] for h in mp['headers']},
                         {'CA35', 'CM33', 'CM0'})


if __name__ == '__main__':
    unittest.main()
