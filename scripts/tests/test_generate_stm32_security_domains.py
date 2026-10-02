"""Security-domain snapshot: only pinned TrustZone alias views, never invented."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'scripts' / 'generate-stm32-security-domains.py'
SPEC = importlib.util.spec_from_file_location('stm32_security_domains', SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

HEADER_EVIDENCE = ROOT / '.embedra/evidence/tasks/T039-memory-header-evidence.json'
MEMORY_PLANS = ROOT / 'catalogs/stm32/2026-09-29/memory-plans.json'
CURATED = ROOT / 'catalogs/stm32/2026-09-29/curated-catalog.json'
SELECTION = ROOT / 'catalogs/stm32/2026-09-29/selection.json'
INTERRUPTS = ROOT / 'catalogs/stm32/2026-09-28/cmsis-interrupts.json'
OUTPUT = ROOT / 'catalogs/stm32/2026-09-29/security-domains.json'


def generate(**overrides):
    inputs = {
        'header_evidence': HEADER_EVIDENCE,
        'memory_plans': MEMORY_PLANS,
        'curated': CURATED,
        'selection': SELECTION,
        'interrupts': INTERRUPTS,
    }
    inputs.update(overrides)
    return MODULE.generate(**inputs)


class SecurityDomainTests(unittest.TestCase):
    def test_committed_snapshot_regenerates(self):
        generated = MODULE.canonical(generate())
        self.assertEqual(OUTPUT.read_bytes(), generated)
        self.assertEqual(MODULE.sha(generated),
                         (OUTPUT.parent / 'security-domains.sha256').read_text().strip())

    def test_alias_and_unavailable_partitions_cover_the_selection(self):
        data = json.loads(OUTPUT.read_bytes())
        records = data['records']
        self.assertEqual(53, len(records))
        alias = [r for r in records if r['status'] == 'ALIAS_VIEWS_PINNED']
        unavailable = [r for r in records if r['status'] == 'UNAVAILABLE']
        self.assertEqual(19, len(alias))
        self.assertEqual(34, len(unavailable))
        self.assertEqual(19, data['aliasViewParts'])
        self.assertEqual(34, data['unavailableParts'])
        for record in alias:
            self.assertIsNone(record['reason'])
            self.assertTrue(record['sourceHeaders'])
            self.assertTrue(record['windows'])
        for record in unavailable:
            self.assertTrue(record['reason'])
            self.assertEqual([], record['windows'])
            self.assertEqual([], record['unresolvedAliasSymbols'])
            self.assertEqual([], record['veneerEvidence']['transitions'])
            self.assertIsNone(record['veneerEvidence']['secureFaultException'])

    def test_windows_cite_pinned_header_symbols_and_pair_t039_aliases(self):
        data = json.loads(OUTPUT.read_bytes())
        plans = json.loads(MEMORY_PLANS.read_bytes())
        plan_by_part = {r['exactPart']: r for r in plans['records']}
        for record in data['records']:
            plan = plan_by_part[record['exactPart']]
            headers = {h['path']: h for h in record['sourceHeaders']}
            for window in record['windows']:
                self.assertEqual('SECURE', window['attribute'])
                self.assertEqual('ALIAS_APERTURE', window['boundaryKind'])
                self.assertEqual('UNRESOLVED_CONFIGURATION_DEPENDENT',
                                 window['partitionState'])
                self.assertGreater(window['size'], 0)
                self.assertLessEqual(window['start'] + window['size'], 0x1_0000_0000)
                self.assertTrue(window['baseSymbol'].endswith('_BASE_S'))
                self.assertTrue(window['baseDeclaration'])
                self.assertGreater(window['baseLine'], 0)
                self.assertIn(window['headerPath'], headers)
                aliases = {a['id']: a for a in plan['aliases']}
                self.assertTrue(window['pairedAliasIds'])
                for alias_id in window['pairedAliasIds']:
                    alias = aliases[alias_id]
                    self.assertEqual(window['pairedRegionId'], alias['target'])
                    self.assertEqual(window['start'], alias['start'])
                    self.assertEqual(window['size'], alias['size'])

    def test_alias_parts_have_secure_fault_evidence_and_no_fabricated_boundary(self):
        data = json.loads(OUTPUT.read_bytes())
        for record in data['records']:
            if record['status'] != 'ALIAS_VIEWS_PINNED':
                continue
            secure_fault = record['veneerEvidence']['secureFaultException']
            self.assertEqual('SecureFault_IRQn', secure_fault['name'])
            self.assertEqual(-9, secure_fault['number'])
            self.assertEqual('UNAVAILABLE', record['veneerEvidence']['status'])
            self.assertEqual('UNAVAILABLE', record['nonSecureCallable']['status'])
            # The NSC boundary is configuration-dependent and is never guessed.
            self.assertEqual('NSC_REGION_CONFIGURATION_DEPENDENT',
                             record['veneerEvidence']['reason'])
            self.assertEqual([], record['veneerEvidence']['transitions'])

    def test_unresolved_alias_symbols_are_named_with_a_reason(self):
        data = json.loads(OUTPUT.read_bytes())
        reasons = set()
        symbols = set()
        for record in data['records']:
            for item in record['unresolvedAliasSymbols']:
                symbols.add(item['symbol'])
                reasons.add(item['reason'])
        self.assertIn('FLASH_OBK_BASE_S', symbols)
        self.assertLessEqual(reasons, {'NO_NS_COUNTERPART',
                                       'NO_T039_REGION_AT_NS_BASE',
                                       'NO_T039_SECURE_VIEW_ALIAS_AT_S_BASE'})

    def test_tampered_pinned_input_fails_closed(self):
        for name, path in (('header_evidence', HEADER_EVIDENCE),
                           ('memory_plans', MEMORY_PLANS),
                           ('curated', CURATED),
                           ('selection', SELECTION),
                           ('interrupts', INTERRUPTS)):
            with tempfile.TemporaryDirectory() as folder:
                tampered = Path(folder) / path.name
                tampered.write_bytes(path.read_bytes() + b' ')
                with self.assertRaisesRegex(MODULE.SecurityDomainError, 'digest'):
                    generate(**{name: tampered})

    def test_regeneration_is_deterministic(self):
        first = MODULE.canonical(generate())
        second = MODULE.canonical(generate())
        self.assertEqual(first, second)

    def test_unknown_part_record_is_rejected(self):
        curated = json.loads(CURATED.read_bytes())
        curated['records'] = curated['records'][:-1]
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'curated-catalog.json'
            path.write_bytes(MODULE.canonical(curated))
            original = MODULE.EXPECTED_CURATED_SHA256
            MODULE.EXPECTED_CURATED_SHA256 = MODULE.sha(path.read_bytes())
            try:
                with self.assertRaisesRegex(MODULE.SecurityDomainError, 'selection'):
                    generate(curated=path)
            finally:
                MODULE.EXPECTED_CURATED_SHA256 = original


if __name__ == '__main__':
    unittest.main()
