"""Pinned memory evidence keeps aliases, register identities, and alternatives."""

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    'memory_headers', ROOT / 'scripts/generate-stm32-memory-header-evidence.py')
GEN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GEN)


class MemoryHeaderEvidenceTest(unittest.TestCase):
    def test_register_alias_and_legacy_comments_are_preserved_without_evaluation(self):
        data = b'''#define NVM_BASE (0x10040000U) /* Main FLASH */
#define FLASH_BASE (APB0PERIPH_BASE + 0x1000U) /* registers */
#define FLASH_BANK2_BASE (0x08100000UL) /* legacy only, unavailable */
#define SRAM1_BASE (SRAM_BASE + 0x3000U)
#define OB_BASE 0x1FFFF800UL
#define RCC_AHB1ENR_SRAMEN (1U << 2)
'''
        rows = GEN.declarations(data)
        self.assertEqual(['NVM_BASE', 'FLASH_BASE', 'FLASH_BANK2_BASE',
                          'SRAM1_BASE', 'OB_BASE'], [r['name'] for r in rows])
        self.assertIn('legacy only, unavailable', rows[2]['declaration'])
        self.assertEqual(4, rows[3]['line'])
        self.assertNotIn('start', rows[0])

    def test_security_alternatives_keep_preprocessor_branch_history(self):
        rows = GEN.declarations(b'''#ifndef DEVICE_H
#define DEVICE_H
#if defined(SECURE)
#define SRAM_BASE 0x30000000U
#elif defined(OTHER)
#define SRAM_BASE 0x40000000U
#else
#define SRAM_BASE 0x20000000U
#endif
#endif
''')
        self.assertEqual(3, len(rows))
        self.assertEqual(['#if defined(SECURE)', '#elif defined(OTHER)', '#else'],
                         rows[2]['conditions'][1])
        self.assertEqual([['#ifndef DEVICE_H'], ['#if defined(SECURE)']],
                         rows[0]['conditions'])

    def test_secure_views_and_virtual_buffers_are_not_discarded(self):
        rows = GEN.declarations(b'''#define DTCM_BASE_NS 0x20000000UL
#define DTCM_BASE_S 0x30000000UL
#define GFXMMU_VIRTUAL_BUFFER0_BASE_NS 0x25000000UL /* virtual */
#define CACHEAXI_RAM_BASE_S 0x343C0000UL /* NPU cache RAM */
''')
        self.assertEqual(4, len(rows))
        self.assertIn('virtual', rows[2]['declaration'])

    def test_invalid_conditions_and_oversized_headers_are_rejected(self):
        for data in (b'#else', b'#endif', b'#if A'):
            with self.assertRaises(ValueError):
                GEN.declarations(data)
        with self.assertRaises(ValueError):
            GEN.declarations(b' ' * (GEN.MAX_HEADER_BYTES + 1))

    def test_multiline_hardware_size_expression_is_preserved(self):
        data = b'#define FLASH_SIZE (READ_SIZE ? \\' + b'\n    0x80000U : READ_SIZE)\n'
        rows = GEN.declarations(data)
        self.assertEqual(1, len(rows))
        self.assertIn('\n    0x80000U : READ_SIZE)', rows[0]['declaration'])
        with self.assertRaises(ValueError):
            GEN.declarations(b'#define FLASH_SIZE value \\')

    def test_manifest_digest_failure_is_not_treated_as_new_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            changed = Path(directory) / 'catalog.json'
            changed.write_bytes(GEN.CATALOG.read_bytes() + b' ')
            with self.assertRaisesRegex(ValueError, 'pinned digest'):
                GEN.generate(directory, catalog_path=changed)

    def test_snapshot_pins_every_selected_header_and_keeps_wl3r_alternatives(self):
        snapshot = json.loads((ROOT / '.embedra/evidence/tasks/'
                               'T039-memory-header-evidence.json').read_text())
        catalog = json.loads(GEN.CATALOG.read_text())
        index = json.loads(GEN.INDEX.read_text())
        self.assertEqual({r['exactPart'] for r in catalog['records']},
                         {r['exactPart'] for r in snapshot['records']})
        self.assertEqual(48, len(snapshot['sources']))
        for name, source in snapshot['sources'].items():
            self.assertEqual(index['headers'][name]['sha256'], source['sha256'])
        row = next(r for r in snapshot['records'] if r['exactPart'] == 'STM32WL3RKBV6')
        self.assertEqual(2, len(row['headers']))
        self.assertEqual('DECLARATIONS_ONLY_UNREVIEWED', row['status'])

    def test_ephemeral_sources_regenerate_identical_evidence_and_reject_changes(self):
        sources = Path('/tmp/embedra-t039-headers')
        if not sources.is_dir():
            self.skipTest('ephemeral pinned headers absent')
        generated = GEN.generate(sources)
        committed = json.loads((ROOT / '.embedra/evidence/tasks/'
                                'T039-memory-header-evidence.json').read_text())
        self.assertEqual(committed, generated)
        with tempfile.TemporaryDirectory() as directory:
            first = json.loads(GEN.CATALOG.read_text())['records'][0]['interruptHeaders'][0]
            changed = Path(directory) / first
            changed.parent.mkdir(parents=True)
            changed.write_bytes((sources / first).read_bytes() + b' ')
            with self.assertRaisesRegex(ValueError, 'header differs'):
                GEN.generate(directory)


if __name__ == '__main__':
    unittest.main()
