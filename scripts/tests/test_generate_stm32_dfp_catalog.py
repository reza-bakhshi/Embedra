"""Redistributable ST DFP exact-part extraction contracts."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import xml.etree.ElementTree as ET

SCRIPT=Path(__file__).resolve().parents[1]/'generate-stm32-dfp-catalog.py'
spec=importlib.util.spec_from_file_location('stm32_dfp',SCRIPT)
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
SAMPLE=b'''<package><vendor>STMicroelectronics</vendor><devices><family Dfamily="C5"><processor Dcore="Cortex-M33" Dtz="NO_TZ"/><subFamily DsubFamily="C53"><debug svd="SVD/STM32C531.svd"/><environment><idcode id="0x44F"/></environment><device Dname="STM32C531CB"><memory name="FLASH" start="0x08000000" size="0x20000"/><memory name="SRAM" start="0x20000000" size="0x10000"/><variant Dvariant="STM32C531CBT6"><feature type="QFP" name="LQFP48"/><environment><extra-attribute name="PPN" value="STM32C531CBTx"/></environment></variant></device></subFamily></family></devices></package>'''

class DfpTests(unittest.TestCase):
    def test_exact_variant_memory_package_and_device_id(self):
        parts,svds=module.parse_pdsc(SAMPLE)
        self.assertEqual(len(parts),1)
        p=parts[0]
        self.assertEqual(p['exactPart'],'STM32C531CBT6')
        self.assertEqual(p['referencePattern'],'STM32C531CBTx')
        self.assertEqual(p['deviceIds'],['0x44F'])
        self.assertEqual(p['memories']['FLASH']['size'],131072)
        self.assertEqual(p['packageDescriptions'],['LQFP48'])
        self.assertEqual(svds,['SVD/STM32C531.svd'])

    def test_duplicate_and_nonexact_rejected(self):
        with self.assertRaisesRegex(module.DfpError,'missing/duplicate'):
            module.parse_pdsc(SAMPLE.replace(b'</device>',b'<variant Dvariant="STM32C531CBT6"/></device>'))
        with self.assertRaisesRegex(module.DfpError,'non-exact'):
            module.parse_pdsc(SAMPLE.replace(b'STM32C531CBT6',b'STM32C531CBTx'))

    def test_malformed_entity_and_depth_rejected(self):
        with self.assertRaisesRegex(module.DfpError,'malformed'):
            module.parse_pdsc(b'<package>')
        with tempfile.TemporaryDirectory() as folder:
            p=Path(folder)/'bad.pdsc';p.write_bytes(b'<!DOCTYPE package><package/>')
            with self.assertRaisesRegex(module.DfpError,'DTD/entity'):
                module.bounded(p,module.MAX_PDSC_BYTES)
        root=ET.Element('root');node=root
        for _ in range(70):node=ET.SubElement(node,'child')
        with self.assertRaisesRegex(module.DfpError,'complexity'):
            module.check_xml_complexity(root)

    def test_snapshot_integrity_and_c5_coverage(self):
        p=SCRIPT.parents[1]/'catalogs/stm32/2026-09-28/c5-exact-parts.json'
        data=p.read_bytes();x=json.loads(data)
        self.assertEqual(module.sha(data),(p.parent/'c5-exact-parts.sha256').read_text().strip())
        self.assertEqual(len(x['parts']),157)
        self.assertEqual(len(x['svdFiles']),9)
        self.assertEqual(len({v['exactPart'] for v in x['parts']}),157)
        self.assertEqual({v['deviceIds'][0] for v in x['parts']},{'0x44E','0x44F','0x45A'})

if __name__=='__main__':unittest.main()
