"""ST-authored SVD indexing contracts."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SCRIPT=Path(__file__).resolve().parents[1]/'generate-stm32-svd-rules.py'
spec=importlib.util.spec_from_file_location('stm32_svd',SCRIPT)
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
SAMPLE='''<device><name>STM32H745</name><cpu><name>CM7</name></cpu><peripherals><peripheral><name>GPIOA</name><interrupt><name>GPIO_IRQn</name><value>7</value></interrupt><registers><register derivedFrom="BASE"><name>REG</name><dim>2</dim><fields><field><name>F</name></field></fields></register></registers></peripheral></peripherals></device>'''

class SvdTests(unittest.TestCase):
    def test_parse_features_and_interrupts(self):
        with tempfile.TemporaryDirectory() as folder:
            p=Path(folder)/'STM32H745_CM7.svd';p.write_text(SAMPLE)
            x=module.parse_svd(p)
            self.assertEqual(x['cpu'],'CM7')
            self.assertEqual(x['interrupts'],[{'name':'GPIO_IRQn','number':7}])
            self.assertEqual(x['features']['derivedFrom'],1)
            self.assertEqual(x['features']['dim'],1)

    def test_malformed_and_dtd_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            p=Path(folder)/'bad.svd';p.write_text('<device>')
            with self.assertRaisesRegex(module.SvdError,'malformed'):
                module.parse_svd(p)
            p.write_text('<!DOCTYPE x><device/>')
            with self.assertRaisesRegex(module.SvdError,'DTD/entity'):
                module.parse_svd(p)

    def test_reference_matching_preserves_core_variants(self):
        self.assertTrue(module.matches('STM32H745XIHx','STM32H745_CM4'))
        self.assertTrue(module.matches('STM32H745XIHx','STM32H745_CM7'))
        self.assertFalse(module.matches('STM32H745XIHx','STM32H743'))

    def test_snapshot_digest_and_unresolved_coverage(self):
        p=SCRIPT.parents[1]/'catalogs/stm32/2026-09-28/svd-rules.json'
        data=p.read_bytes();x=json.loads(data)
        self.assertEqual(module.sha(data),(p.parent/'svd-rules.sha256').read_text().strip())
        self.assertEqual(len(x['files']),196)
        self.assertEqual(len(x['mappings']),2240)
        self.assertTrue(any(m['status']=='UNRESOLVED' for m in x['mappings']))

if __name__=='__main__':unittest.main()
