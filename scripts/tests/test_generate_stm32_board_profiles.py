"""Board-profile snapshot: pinned external-memory facts, no invented data."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'scripts' / 'generate-stm32-board-profiles.py'
SPEC = importlib.util.spec_from_file_location('stm32_board_profiles', SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

INDEX = ROOT / 'catalogs/stm32/sources/board-index.json'
OUTPUT = ROOT / 'catalogs/stm32/2026-09-29/board-profiles.json'


class BoardProfileTests(unittest.TestCase):
    def test_committed_snapshot_regenerates(self):
        generated = MODULE.canonical(MODULE.generate(INDEX))
        self.assertEqual(OUTPUT.read_bytes(), generated)
        self.assertEqual(MODULE.sha(generated),
                         (OUTPUT.parent / 'board-profiles.sha256').read_text().strip())

    def test_reviewed_profiles_have_pinned_source_and_bounded_regions(self):
        data = json.loads(OUTPUT.read_bytes())
        reviewed = [p for p in data['profiles']
                    if p['status'] == 'EXTERNAL_MEMORY_REVIEWED']
        self.assertEqual(9, len(reviewed))
        self.assertEqual(9, data['reviewedProfiles'])
        self.assertEqual(MODULE.EXPECTED_BOARD_INDEX_SHA256, data['boardIndexSha256'])
        self.assertEqual(MODULE.EXPECTED_SELECTION_SHA256, data['selectionSha256'])
        for profile in reviewed:
            self.assertTrue(profile['board'])
            self.assertTrue(profile['bsp']['repository'])
            self.assertRegex(profile['bsp']['revision'], r'^[0-9a-f]{40}$')
            self.assertTrue(profile['boardSource']['sourcePath'].startswith('boards/'))
            self.assertRegex(profile['boardSource']['sourceSha256'], r'^[0-9a-f]{64}$')
            self.assertTrue(profile['externalRegions'])
            for region in profile['externalRegions']:
                self.assertGreater(region['size'], 0)
                self.assertLessEqual(region['start'] + region['size'], 0x1_0000_0000)
                self.assertTrue(region['device'])
                self.assertTrue(region['startEvidence'])
                self.assertTrue(region['sizeEvidence'])

    def test_no_external_region_overlaps_another(self):
        data = json.loads(OUTPUT.read_bytes())
        for profile in data['profiles']:
            ranges = sorted((r['start'], r['start'] + r['size'])
                            for r in profile['externalRegions'])
            for (_, left_end), (right_start, _) in zip(ranges, ranges[1:]):
                self.assertLessEqual(left_end, right_start, profile['exactPart'])

    def test_unavailable_profiles_stay_explicit_with_reason(self):
        data = json.loads(OUTPUT.read_bytes())
        unavailable = [p for p in data['profiles'] if p['status'] == 'UNAVAILABLE']
        self.assertTrue(unavailable)
        for profile in unavailable:
            self.assertEqual([], profile['externalRegions'])
            self.assertTrue(profile['reason'])
            self.assertIsNone(profile['bsp'])

    def test_oversight_wildcard_or_family_link_is_rejected(self):
        # A tampers with the pinned board index: a non-exact link must fail.
        with tempfile.TemporaryDirectory() as folder:
            tampered = Path(folder) / 'board-index.json'
            tampered.write_bytes(INDEX.read_bytes().replace(b'"cpnStatus":"EXACT"',
                                                            b'"cpnStatus":"REFERENCE_ONLY"', 1))
            # Digest guard fires before any record is read.
            with self.assertRaisesRegex(MODULE.BoardProfileError, 'digest'):
                MODULE.generate(tampered)

    def test_missing_board_link_fails_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            index = json.loads(INDEX.read_bytes())
            for record in index['records']:
                if record.get('board') == 'STM32H735G-DK':
                    record['board'] = 'RENAMED-BOARD'
            tampered = Path(folder) / 'board-index.json'
            tampered.write_bytes(MODULE.canonical(index))
            # Replace the digest pin so the record check is exercised directly.
            original = MODULE.EXPECTED_BOARD_INDEX_SHA256
            MODULE.EXPECTED_BOARD_INDEX_SHA256 = MODULE.sha(tampered.read_bytes())
            try:
                with self.assertRaisesRegex(MODULE.BoardProfileError, 'not an exact board'):
                    MODULE.generate(tampered)
            finally:
                MODULE.EXPECTED_BOARD_INDEX_SHA256 = original

    def test_controller_without_pinned_alias_is_rejected(self):
        with self.assertRaisesRegex(MODULE.BoardProfileError, 'alias'):
            MODULE.external_region(
                {'id': 'X', 'kind': 'EXTERNAL_FLASH_MEMORY_MAPPED',
                 'controller': 'NOT_A_CONTROLLER', 'device': 'D', 'sizeBytes': 16,
                 'writable': True, 'sizeEvidence': 'e'}, {}, 'PART')


if __name__ == '__main__':
    unittest.main()
