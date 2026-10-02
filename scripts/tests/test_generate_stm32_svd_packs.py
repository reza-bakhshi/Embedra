"""STM32 SVD pack transformation and provenance contracts."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'scripts' / 'generate-stm32-svd-packs.py'
SPEC = importlib.util.spec_from_file_location('stm32_svd_packs', SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

SYNTHETIC = b'''<device>
 <name>STM32SYN</name>
 <cpu><name>CM4</name></cpu>
 <size>32</size>
 <access>read-write</access>
 <peripherals>
  <peripheral>
   <name>BASE</name><description>base device</description><groupName>GRP</groupName>
   <baseAddress>0x40000000</baseAddress>
   <addressBlock><offset>0</offset><size>0x400</size></addressBlock>
   <interrupt><name>BASE_IRQn</name><value>7</value><description>base irq</description></interrupt>
   <registers>
    <register>
     <name>CTRL</name><description>control</description><addressOffset>0</addressOffset>
     <fields>
      <field><name>EN</name><description>enable</description><bitOffset>0</bitOffset>
       <bitWidth>1</bitWidth><readAction>clear</readAction>
       <enumeratedValues>
        <enumeratedValue><name>Off</name><value>0</value></enumeratedValue>
        <enumeratedValue><name>On</name><value>1</value><description>on</description></enumeratedValue>
       </enumeratedValues>
      </field>
      <field derivedFrom="EN"><name>EN2</name><bitOffset>1</bitOffset><bitWidth>1</bitWidth></field>
     </fields>
    </register>
    <register><name>ARR%s</name><addressOffset>0x10</addressOffset><dim>2</dim>
     <dimIncrement>4</dimIncrement><description>array</description></register>
    <cluster><name>CH%s</name><addressOffset>0x20</addressOffset><dim>2</dim>
     <dimIncrement>0x10</dimIncrement>
     <register><name>CFG</name><addressOffset>0</addressOffset></register>
     <cluster><name>SUB%s</name><addressOffset>8</addressOffset><dim>2</dim>
      <dimIncrement>4</dimIncrement>
      <register><name>LEAF</name><addressOffset>0</addressOffset></register></cluster>
    </cluster>
    <register alternateRegister="CTRL"><name>CTRL_ALT</name><addressOffset>0</addressOffset>
     <size>16</size>
     <fields><field><name>X</name><bitOffset>0</bitOffset><bitWidth>4</bitWidth></field></fields>
    </register>
   </registers>
  </peripheral>
  <peripheral derivedFrom="BASE"><name>DERIVED</name><baseAddress>0x40001000</baseAddress>
   <interrupt><name>DERIVED_IRQn</name><value>8</value></interrupt></peripheral>
 </peripherals>
</device>'''


class PackTransformTests(unittest.TestCase):
    def test_inheritance_arrays_clusters_and_enums(self):
        device = MODULE.parse_device(SYNTHETIC, 'syn/STM32SYN.svd',
                                     MODULE.sha(SYNTHETIC))
        self.assertEqual('STM32SYN', device['deviceName'])
        self.assertEqual('CM4', device['cpu'])
        self.assertEqual(2, len(device['peripherals']))
        base = next(item for item in device['peripherals'] if item['name'] == 'BASE')
        derived = next(item for item in device['peripherals'] if item['name'] == 'DERIVED')
        # Peripheral derivedFrom inherits the base registers but overrides baseAddress.
        self.assertEqual(0x40001000, derived['baseAddress'])
        self.assertEqual(len(base['registers']), len(derived['registers']))
        addresses = {register['name']: register['address']
                     for register in base['registers']}
        self.assertEqual(0x40000000, addresses['CTRL'])
        self.assertEqual(0x40000010, addresses['ARR0'])
        self.assertEqual(0x40000014, addresses['ARR1'])
        self.assertEqual(0x40000020, addresses['CH0_CFG'])
        self.assertEqual(0x40000028, addresses['CH0_SUB0_LEAF'])
        self.assertEqual(0x4000002C, addresses['CH0_SUB1_LEAF'])
        self.assertEqual(0x40000030, addresses['CH1_CFG'])
        self.assertEqual(0x40000000, addresses['CTRL_ALT'])
        ctrl = next(register for register in base['registers']
                    if register['name'] == 'CTRL')
        self.assertEqual(2, len(ctrl['fields']))
        self.assertEqual('clear', ctrl['fields'][0]['readAction'])
        # Field derivedFrom copies the base enumeration.
        self.assertEqual(2, len(ctrl['fields'][1]['enumeratedValues']))
        alternate = next(register for register in base['registers']
                         if register['name'] == 'CTRL_ALT')
        self.assertEqual('CTRL', alternate['alternateRegister'])
        self.assertEqual(16, alternate['sizeBits'])
        self.assertEqual([{'name': 'BASE_IRQn', 'value': 7,
                           'description': 'base irq'}], base['interrupts'])

    def test_malformed_dtd_and_unsupported_constructs_are_rejected(self):
        with self.assertRaisesRegex(MODULE.SvdError, 'malformed'):
            MODULE.parse_device(b'<device>', 'bad.svd', '0' * 64)
        with self.assertRaisesRegex(MODULE.SvdError, 'DTD/entity'):
            MODULE.parse_device(b'<!DOCTYPE x><device/>', 'bad.svd', '0' * 64)
        with self.assertRaisesRegex(MODULE.SvdError, 'encoding'):
            MODULE.parse_device('<!DOCTYPE x><device/>'.encode('utf-16'),
                                'bad.svd', '0' * 64)
        with self.assertRaisesRegex(MODULE.SvdError, 'encoding'):
            MODULE.parse_device(SYNTHETIC.decode('utf-8').encode('utf-16'),
                                'bad.svd', '0' * 64)
        unsupported = SYNTHETIC.replace(
            b'<bitWidth>1</bitWidth><readAction>clear</readAction>',
            b'<bitWidth>1</bitWidth><writeConstraint/>')
        with self.assertRaisesRegex(MODULE.Unsupported, 'writeConstraint'):
            MODULE.parse_device(unsupported, 'bad.svd', '0' * 64)

    def test_enumerated_value_must_fit_its_field(self):
        broken = SYNTHETIC.replace(b'<value>1</value>',
                                   b'<value>4</value>', 1)
        with self.assertRaisesRegex(MODULE.SvdError, 'does not fit'):
            MODULE.parse_device(broken, 'bad.svd', '0' * 64)

    def _sources(self, folder):
        svd = Path(folder) / 'syn' / 'STM32SYN.svd'
        svd.parent.mkdir(parents=True, exist_ok=True)
        svd.write_bytes(SYNTHETIC)
        curated = Path(folder) / 'curated.json'
        curated.write_bytes(MODULE.canonical({'records': [
            {'exactPart': 'STM32SYN1', 'family': 'STM32SYN'}]}))
        applicability = Path(folder) / 'app.json'
        applicability.write_bytes(MODULE.canonical({
            '$schema': 'urn:embedra:schema:stm32-svd-applicability:1',
            'curatedCatalogSha256': MODULE.sha(curated.read_bytes()),
            'parts': [{
                'exactPart': 'STM32SYN1', 'family': 'STM32SYN',
                'status': 'EXACT_SVD_SHIPPED',
                'svdFiles': [{'deviceName': 'STM32SYN', 'path': 'syn/STM32SYN.svd',
                              'sha256': MODULE.sha(SYNTHETIC), 'cpu': 'CM4'}],
                'reason': None}]}))
        return curated, applicability, Path(folder)

    def test_generate_is_deterministic_and_manifest_is_consistent(self):
        with tempfile.TemporaryDirectory() as folder:
            curated, applicability, root = self._sources(folder)
            out = Path(folder) / 'out'
            written = MODULE.generate(applicability, curated, root, out)
            self.assertEqual(['stm32.stm32syn.svd'], written)
            manifest = json.loads(
                (out / written[0] / '1.0.0' / 'pack.json').read_bytes())
            content = (out / written[0] / '1.0.0' / 'registers.json').read_bytes()
            self.assertEqual(MODULE.sha(content), manifest['files'][0]['sha256'])
            descriptor = (f"registers.json\x00{len(content)}\x00"
                          f"{manifest['files'][0]['sha256']}\n").encode()
            self.assertEqual(MODULE.sha(descriptor), manifest['contentDigest'])
            self.assertEqual('Apache-2.0', manifest['provenance']['license'])
            self.assertEqual('ALLOWED', manifest['provenance']['redistribution'])
            self.assertEqual(['STM32SYN1'], manifest['supportedDevices'])
            first = content
            MODULE.generate(applicability, curated, root, out)
            self.assertEqual(first, (out / written[0] / '1.0.0'
                                     / 'registers.json').read_bytes())

    def test_source_digest_mismatch_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            curated, applicability, root = self._sources(folder)
            (root / 'syn' / 'STM32SYN.svd').write_bytes(SYNTHETIC + b' ')
            with self.assertRaisesRegex(MODULE.SvdError, 'digest mismatch'):
                MODULE.generate(applicability, curated, root, Path(folder) / 'out')


if __name__ == '__main__':
    unittest.main()
