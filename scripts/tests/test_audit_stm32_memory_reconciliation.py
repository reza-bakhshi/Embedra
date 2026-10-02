"""Reject the observed T039 alias/capacity errors in partial review evidence."""

import copy
import importlib.util
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    'reconciliation', ROOT / 'scripts/audit-stm32-memory-reconciliation.py')
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)


class ReconciliationTest(unittest.TestCase):
    def setUp(self):
        self.review = json.loads((AUDIT.EVIDENCE / 'T039-memory-reconciliation.json').read_text())
        self.catalog = json.loads((ROOT / 'catalogs/stm32/2026-09-29/curated-catalog.json').read_text())
        self.candidates = json.loads((AUDIT.EVIDENCE / 'T039-memory-candidates.json').read_text())
        self.headers = json.loads((AUDIT.EVIDENCE / 'T039-memory-header-evidence.json').read_text())

    def check(self):
        return AUDIT.audit(self.review, self.catalog, self.candidates, self.headers)

    def part(self, name):
        return next(r for r in self.review['records'] if r['exactPart'] == name)

    def test_pinned_partial_evidence_does_not_imply_ready_maps(self):
        result = AUDIT.audit_files()
        self.assertEqual(53, result['selectedParts'])
        self.assertEqual(11, result['partsWithPartialRegionFacts'])
        self.assertEqual(0, result['completeRuntimeMaps'])

    def test_ccm_alias_cannot_inflate_g491_capacity(self):
        self.part('STM32G491RET6')['ramCapacityReview']['physicalKiB'] = 128
        with self.assertRaisesRegex(ValueError, 'capacity'):
            self.check()

    def test_wb05_inherited_debugger_window_is_not_another_bank(self):
        row = self.part('STM32WB05KZV6TR')
        extra = copy.deepcopy(row['knownRegions'][0])
        extra.update(id='DFP_SRAM0_WINDOW', start=0x20000018, size=0x2fe8)
        row['knownRegions'].append(extra)
        with self.assertRaisesRegex(ValueError, 'overlap'):
            self.check()

    def test_flash_alias_target_must_exist_and_cannot_be_an_alias(self):
        row = self.part('STM32F756ZGT6')
        alias = next(r for r in row['knownRegions'] if 'aliasOf' in r)
        alias['aliasOf'] = alias['id']
        with self.assertRaisesRegex(ValueError, 'alias must'):
            self.check()

    def test_wrong_part_scope_and_source_symbol_are_rejected(self):
        row = self.part('STM32F103C8T6')
        row['knownRegions'][0]['headerSymbols'] = ['NVM_BASE']
        with self.assertRaisesRegex(ValueError, 'absent header'):
            self.check()
        row['knownRegions'][0]['headerSymbols'] = ['FLASH_BASE']
        row['nameReview']['selectedDevicePattern'] = 'STM32F103RETx'
        with self.assertRaisesRegex(ValueError, 'absent device'):
            self.check()

    def test_missing_part_and_premature_promotion_are_rejected(self):
        self.review['records'].pop()
        with self.assertRaisesRegex(ValueError, 'every exact'):
            self.check()
        self.setUp()
        self.part('STM32F103C8T6')['remaining'] = []
        with self.assertRaisesRegex(ValueError, 'mandatory evidence gaps'):
            self.check()

    def test_f103_c8_keeps_exact_capacity_instead_of_shared_header_maximum(self):
        c8 = self.part('STM32F103C8T6')
        cb = self.part('STM32F103CBT6')
        self.assertEqual(65536, c8['knownRegions'][0]['size'])
        self.assertEqual(131072, cb['knownRegions'][0]['size'])
        self.assertEqual(c8['headers'], cb['headers'])
        self.assertEqual('UNKNOWN', c8['otpApplicability'])

    def test_n6_source_alias_error_is_retained_without_silent_repair(self):
        row = self.part('STM32N657X0H3Q')
        source = next(r for r in self.candidates['records'] if r['exactPart'] == row['exactPart'])
        declaration = next(m for m in source['candidates'][0]['memories'] if m['name'] == 'DTCM_S')
        self.assertEqual('ITCM_NS', declaration['alias'])
        self.assertEqual(declaration['alias'], row['sourceAnomalies'][0]['declaredAlias'])
        header = self.headers['sources'][row['headers'][0]]
        symbols = {d['name']: d['declaration'] for d in header['declarations']}
        self.assertIn('0x20000000', symbols['DTCM_BASE_NS'])
        self.assertIn('0x30000000', symbols['DTCM_BASE_S'])
        self.assertEqual([], row['knownRegions'])

    def test_wl33_tx_only_variant_is_excluded_from_selected_cpn_review(self):
        review = self.part('STM32WL33CCV6TR')['nameReview']
        self.assertEqual('STM32WL33CCVx', review['selectedDevicePattern'])
        self.assertEqual(['STM32WL33CCVxX'], review['rejectedDevicePatterns'])
        self.assertEqual('STM32WL33CCV6', review['siliconPart'])


if __name__ == '__main__':
    unittest.main()
