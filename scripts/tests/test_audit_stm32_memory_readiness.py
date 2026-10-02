"""T039 fail-closed catalog memory-readiness checks."""

import importlib.util
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'scripts' / 'audit-stm32-memory-readiness.py'
SPEC = importlib.util.spec_from_file_location('stm32_memory_audit', SCRIPT)
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)


class MemoryReadinessTest(unittest.TestCase):
    def test_curated_snapshot_reports_actual_gaps(self):
        catalog = ROOT / 'catalogs/stm32/2026-09-29/curated-catalog.json'
        result = AUDIT.audit_catalog(catalog)
        self.assertEqual(53, result['recordCount'])
        self.assertEqual(53, result['missingMemoryBanks'])
        self.assertEqual(11, result['unresolvedFlash'])
        self.assertEqual(0, result['readyCount'])
        self.assertIn('STM32C031C6T3', result['incompleteParts'])

    def test_catalog_fail_closed_when_hash_changes(self):
        catalog = ROOT / 'catalogs/stm32/2026-09-29/curated-catalog.json'
        self.assertEqual(AUDIT.CATALOG_SHA256,
                         AUDIT.sha256(catalog.read_bytes()))
        with self.assertRaises(ValueError):
            AUDIT.audit_bytes(catalog.read_bytes() + b' ')

    def test_additive_maps_validate_all_reviewed_exact_parts(self):
        result = AUDIT.audit_catalog(plans_path=AUDIT.PLANS)
        self.assertEqual(53, result['readyCount'])
        self.assertEqual(0, result['missingMemoryBanks'])
        self.assertEqual(11, result['unresolvedFlash'])
        self.assertEqual({}, result['incompleteParts'])

    def test_romless_and_non_mapped_availability_are_explicit(self):
        plans = json.loads(AUDIT.PLANS.read_text())
        romless = next(record for record in plans['records']
                       if record['exactPart'] == 'STM32N657X0H3Q')
        self.assertEqual('UNAVAILABLE', romless['flashAvailability'])
        self.assertEqual([], AUDIT.plan_gaps(romless))
        romless['flashReason'] = ''
        self.assertIn('FLASH_APPLICABILITY_UNKNOWN', AUDIT.plan_gaps(romless))
        wl3r = next(record for record in plans['records']
                    if record['exactPart'] == 'STM32WL3RKBV6')
        self.assertEqual('UNAVAILABLE', wl3r['systemAvailability'])
        self.assertEqual([], AUDIT.plan_gaps(wl3r))
        wl3r['systemReason'] = ''
        self.assertIn('SYSTEM_APPLICABILITY_UNKNOWN', AUDIT.plan_gaps(wl3r))

    def test_configuration_dependent_boot_and_absent_bit_band_are_explicit(self):
        plans = json.loads(AUDIT.PLANS.read_text())
        part = next(record for record in plans['records']
                    if record['exactPart'] == 'STM32F756ZGT6')
        self.assertEqual([], AUDIT.plan_gaps(part))
        part['bitBandReason'] = ''
        self.assertIn('BIT_BAND_APPLICABILITY_UNKNOWN', AUDIT.plan_gaps(part))
        part['bitBandReason'] = 'documented absent'
        part['bootAliasReason'] = ''
        self.assertIn('BOOT_ALIAS_APPLICABILITY_UNKNOWN', AUDIT.plan_gaps(part))

    def test_validation_status_does_not_hide_incomplete_regions(self):
        plans = json.loads(AUDIT.PLANS.read_text())
        part = next(record for record in plans['records'] if record['exactPart'] == 'STM32F103C8T6')
        self.assertEqual([], AUDIT.plan_gaps(part))
        part['regions'] = part['regions'][:1]
        self.assertIn('MANDATORY_REGIONS_MISSING', AUDIT.plan_gaps(part))
        self.assertIn('CAPACITY_CONFLICT_RAM', AUDIT.plan_gaps(part))

    def test_missing_inter_processor_resources_and_core_mismatch_fail(self):
        plans = json.loads(AUDIT.PLANS.read_text())
        dual = next(record for record in plans['records']
                    if record['exactPart'] == 'STM32WB55RGV6')
        self.assertEqual([], AUDIT.plan_gaps(dual))
        del dual['topology']['ipccRegisterRange']
        self.assertIn('INTER_PROCESSOR_RESOURCE_MISSING', AUDIT.plan_gaps(dual))
        dual['topology']['ipccRegisterRange'] = [0, 1]
        dual['topology']['physicalCoreCount'] = 1
        self.assertIn('PROFILE_CORE_COUNT_MISMATCH', AUDIT.plan_gaps(dual))

    def test_invalid_availability_value_and_flash_contradiction_fail(self):
        plans = json.loads(AUDIT.PLANS.read_text())
        part = next(record for record in plans['records'] if record['exactPart'] == 'STM32F401RET6')
        self.assertEqual([], AUDIT.plan_gaps(part))
        bad = json.loads(json.dumps(part))
        bad['flashAvailability'] = 'BOGUS'
        bad['regions'] = [r for r in bad['regions'] if r['kind'] != 'FLASH']
        gaps = AUDIT.plan_gaps(bad)
        self.assertIn('INVALID_FLASH_AVAILABILITY', gaps)
        self.assertIn('FLASH_APPLICABILITY_UNKNOWN', gaps)
        contradictory = json.loads(json.dumps(part))
        contradictory['flashAvailability'] = 'UNAVAILABLE'
        contradictory['flashReason'] = 'documented ROMless'
        self.assertIn('FLASH_REGION_CONTRADICTS_AVAILABILITY', AUDIT.plan_gaps(contradictory))

    def test_configuration_alternatives_and_shared_access_fail_closed(self):
        plans = json.loads(AUDIT.PLANS.read_text())
        h735 = next(record for record in plans['records'] if record['exactPart'] == 'STM32H735IGK6')
        self.assertEqual([], AUDIT.plan_gaps(h735))
        h735['configurationAlternatives']['ITCM_AXI_SHARED']['physicalKiB'] = 128
        self.assertIn('CONFIGURATION_SIZE_MISMATCH', AUDIT.plan_gaps(h735))
        h735['configurationAlternatives']['ITCM_AXI_SHARED']['physicalKiB'] = 192
        h735['configurationAlternatives']['ITCM_AXI_SHARED']['allocations'][
            'ITCM_AXI_SHARED_64_320']['ranges'] = [{'start': 'x', 'size': 1}]
        self.assertIn('INVALID_CONFIGURATION_ALTERNATIVES', AUDIT.plan_gaps(h735))
        h735['regions'].append({'id': 'X', 'kind': 'RAM', 'start': 0x24020000,
                                'size': 0x30000, 'access': 'rwx',
                                'configuration': 'ITCM_AXI_SHARED'})
        del h735['configurationAlternatives']
        self.assertIn('CONFIGURATION_UNDECLARED', AUDIT.plan_gaps(h735))

    def test_allocation_ranges_must_not_overlap_each_other(self):
        plans = json.loads(AUDIT.PLANS.read_text())
        h735 = next(record for record in plans['records'] if record['exactPart'] == 'STM32H735IGK6')
        self.assertEqual([], AUDIT.plan_gaps(h735))
        allocation = h735['configurationAlternatives']['ITCM_AXI_SHARED'][
            'allocations']['ITCM_AXI_SHARED_128_256']
        allocation['ranges'] = [{'start': 0x24020000, 'size': 0x10000},
                                {'start': 0x24020000, 'size': 0x20000}]
        gaps = AUDIT.plan_gaps(h735)
        self.assertIn('CONFIGURATION_RANGE_OVERLAP', gaps)
        wb55 = next(record for record in plans['records'] if record['exactPart'] == 'STM32WB55RGV6')
        del wb55['regions'][1]['sharedAccess']
        self.assertIn('SHARED_ACCESS_MISSING', AUDIT.plan_gaps(wb55))
        wb55['regions'][1]['sharedAccess'] = {'cpu3': 'rw'}
        self.assertIn('INVALID_SHARED_ACCESS', AUDIT.plan_gaps(wb55))

    def test_inter_processor_bounds_must_be_ordered_integers(self):
        plans = json.loads(AUDIT.PLANS.read_text())
        dual = next(record for record in plans['records']
                    if record['exactPart'] == 'STM32WB55RGV6')
        dual['topology']['ipccRegisterRange'] = '0x58000000'
        self.assertIn('INTER_PROCESSOR_RESOURCE_MISSING', AUDIT.plan_gaps(dual))
        dual['topology']['ipccRegisterRange'] = [5, -1]
        self.assertIn('INTER_PROCESSOR_RESOURCE_MISSING', AUDIT.plan_gaps(dual))

    def test_no_missing_fact_is_silently_defaulted(self):
        catalog = json.loads((ROOT / 'catalogs/stm32/2026-09-29/'
                              'curated-catalog.json').read_text())
        part = next(record for record in catalog['records']
                    if record['exactPart'] == 'STM32C031C6T3')
        self.assertIn('FLASH_SIZE_UNPAIRED', AUDIT.gaps(part))
        self.assertIn('MEMORY_BANKS_UNKNOWN', AUDIT.gaps(part))
        self.assertNotIn('PROCESSORS_UNKNOWN', AUDIT.gaps(part))


if __name__ == '__main__':
    unittest.main()
