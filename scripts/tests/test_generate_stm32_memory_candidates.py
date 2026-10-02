"""T039 pinned PDSC candidate extraction, without support promotion."""

import importlib.util
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'scripts' / 'generate-stm32-memory-candidates.py'
SPEC = importlib.util.spec_from_file_location('stm32_memory_candidates', SCRIPT)
GEN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GEN)


class MemoryCandidateTest(unittest.TestCase):
    def test_inherited_memory_is_overridden_by_name_and_variant(self):
        xml = b'''<package><devices><family Dfamily="F"><memory name="SRAM" start="0x20000000" size="0x1000" access="rwx"/><subFamily DsubFamily="S"><device Dname="STM32C051C8Tx"><memory name="Flash" start="0x08000000" size="0x10000" access="rx"/><memory name="SRAM" start="0x20000000" size="0x3000" access="rwx"/><variant Dvariant="STM32C051C8T6"><memory name="OTP" start="0x1fff0000" size="0x100" access="r"/></variant></device></subFamily></family></devices></package>'''
        matches = GEN.match_nodes(GEN.parse_pdsc(xml), 'STM32C051C8T6', 'DIRECT_PATTERN')
        self.assertEqual(1, len(matches))
        self.assertEqual('STM32C051C8T6', matches[0]['devicePattern'])
        memories = matches[0]['memories']
        self.assertEqual(['SRAM', 'Flash', 'OTP'], [x['name'] for x in memories])
        self.assertEqual(0x3000, memories[0]['size'])
        self.assertEqual('STM32C051C8Tx', memories[0]['declaredAt'])

    def test_prefix_match_is_explicit_and_never_direct(self):
        xml = b'<package><devices><family Dfamily="F"><device Dname="STM32F207ZG"><memory name="Flash" start="0x08000000" size="0x100000"/></device></family></devices></package>'
        root = GEN.parse_pdsc(xml)
        self.assertEqual([], GEN.match_nodes(root, 'STM32F207ZGT6', 'DIRECT_PATTERN'))
        matches = GEN.match_nodes(root, 'STM32F207ZGT6', 'PREFIX_CANDIDATE')
        self.assertEqual(1, len(matches))
        self.assertEqual('STM32F207ZG', matches[0]['devicePattern'])
        self.assertTrue(GEN.direct_match('STM32H750XBHx', 'STM32H750XBH6'))
        self.assertFalse(GEN.direct_match('STM32H750XBHx', 'STM32H750ABH6'))

    def test_alias_and_alternate_view_are_preserved(self):
        xml = b'<package><devices><family Dfamily="F"><device Dname="STM32F756ZG"><memory name="Flash" start="0x08000000" size="0x100000"/><memory name="ITCM_Flash" start="0x00200000" size="0x100000" alias="Flash"/></device></family></devices></package>'
        match = GEN.match_nodes(GEN.parse_pdsc(xml), 'STM32F756ZGT6', 'PREFIX_CANDIDATE')[0]
        self.assertEqual(2, len(match['memories']))
        self.assertEqual('Flash', match['memories'][1]['alias'])
        self.assertNotIn('physicalFlashBytes', match)

    def test_package_variants_match_complete_names_without_suffix_inference(self):
        for pattern, part in [('STM32F207ZGTx', 'STM32F207ZGT6'),
                              ('STM32F401RETx', 'STM32F401RET6'),
                              ('STM32F756ZGTx', 'STM32F756ZGT6')]:
            self.assertTrue(GEN.direct_match(pattern, part))
            self.assertFalse(GEN.direct_match(pattern, part + 'TR'))
            self.assertFalse(GEN.direct_match(pattern, part[:-2] + 'U6'))

    def test_direct_matches_are_not_misclassified_in_pinned_audit(self):
        audit = json.loads((ROOT / '.embedra/evidence/tasks/'
                           'T039-dfp-source-audit.json').read_text())
        direct = {part for pack in audit['packs'] for part in pack['directPatternParts']}
        prefix = {part for pack in audit['packs'] for part in pack['prefixCandidateParts']}
        self.assertEqual(46, len(direct))
        self.assertEqual({'STM32WB05KZV6TR', 'STM32WB07CCV6TR',
                          'STM32WB09KEV6TR', 'STM32WL33CCV6TR'}, prefix)
        self.assertFalse(direct & prefix)

    def test_reject_dtd_and_entity(self):
        with self.assertRaises(ValueError):
            GEN.parse_pdsc(b'<!DOCTYPE package [<!ENTITY x "bad">]><package/>')
        with self.assertRaises(ValueError):
            GEN.parse_pdsc('<!DOCTYPE package [<!ENTITY x "bad">]><package/>'
                           .encode('utf-16'))

    def test_local_sources_match_pinned_hashes(self):
        audit = json.loads((ROOT / '.embedra/evidence/tasks/T039-dfp-source-audit.json').read_text())
        sources = Path('/tmp/embedra-t039-dfp-audit')
        if not sources.is_dir():
            self.skipTest('ephemeral pinned source download absent')
        for pack in audit['packs']:
            name = pack['repository'].split('/')[-1].removesuffix('.git') + '.pdsc'
            self.assertEqual(pack['pdscSha256'], GEN.sha256((sources / name).read_bytes()))

    def test_generated_snapshot_keeps_missing_and_ambiguous_parts_visible(self):
        snapshot = json.loads((ROOT / '.embedra/evidence/tasks/'
                               'T039-memory-candidates.json').read_text())
        self.assertEqual(53, len(snapshot['records']))
        records = {row['exactPart']: row for row in snapshot['records']}
        self.assertEqual('NO_DFP_MATCH', records['STM32F103C8T6']['status'])
        self.assertEqual(2, len(records['STM32WL33CCV6TR']['candidates']))
        f756 = records['STM32F756ZGT6']['candidates'][0]
        self.assertIn('ITCM_Flash', [m['name'] for m in f756['memories']])
        self.assertNotIn('physicalFlashBytes', f756)
        wb0 = records['STM32WB05KZV6TR']['candidates'][0]
        self.assertEqual(0x10040000, next(m['start'] for m in wb0['memories']
                                          if m['name'] == 'Main_Flash'))


if __name__ == '__main__':
    unittest.main()
