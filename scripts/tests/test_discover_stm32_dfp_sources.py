"""ST STM32 DFP source-discovery contracts with synthetic GitHub listings."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'discover-stm32-dfp-sources.py'
spec = importlib.util.spec_from_file_location('stm32_dfp_discovery', SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def repository(name, license_id='NOASSERTION', archived=False):
    return {
        'name': name,
        'archived': archived,
        'default_branch': 'main',
        'license': {'spdx_id': license_id} if license_id else None,
        'html_url': 'https://github.com/STMicroelectronics/' + name,
    }


class DiscoveryTests(unittest.TestCase):
    def test_known_repository_is_not_a_candidate(self):
        report = module.audit([repository('stm32c5xx-dfp', 'BSD-3-Clause')],
                              module.DEFAULT_KNOWN)
        self.assertEqual(report['known'], ['stm32c5xx-dfp'])
        self.assertEqual(report['candidates'], [])

    def test_new_repository_is_a_review_candidate(self):
        report = module.audit([
            repository('stm32c5xx-dfp', 'BSD-3-Clause'),
            repository('STM32C0xx-DFP', 'BSD-3-Clause'),
            repository('STM32CubeU5-V2-Preview'),
            repository('stm32h7-hal-driver', 'BSD-3-Clause'),
        ], module.DEFAULT_KNOWN)
        self.assertEqual([row['name'] for row in report['candidates']],
                         ['STM32C0xx-DFP'])
        self.assertEqual(report['candidates'][0]['license'], 'BSD-3-Clause')

    def test_allowlist_is_case_insensitive(self):
        report = module.audit([repository('STM32C5XX-DFP')], ('stm32c5xx-dfp',))
        self.assertEqual(report['known'], ['STM32C5XX-DFP'])
        self.assertEqual(report['candidates'], [])

    def test_items_wrapper_and_determinism(self):
        payload = {'items': [repository('stm32zzxx-dfp'),
                             repository('stm32aaxx-dfp')]}
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'repos.json'
            path.write_text(json.dumps(payload))
            first = module.canonical(module.audit(
                module.load_repositories(path), module.DEFAULT_KNOWN))
            second = module.canonical(module.audit(
                module.load_repositories(path), module.DEFAULT_KNOWN))
            self.assertEqual(first, second)
            report = json.loads(first)
            self.assertEqual([row['name'] for row in report['candidates']],
                             ['stm32aaxx-dfp', 'stm32zzxx-dfp'])

    def test_malformed_listing_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'repos.json'
            path.write_text('{not json')
            with self.assertRaisesRegex(module.DiscoveryError, 'malformed'):
                module.load_repositories(path)
            path.write_text('42')
            with self.assertRaisesRegex(module.DiscoveryError, 'unexpected shape'):
                module.load_repositories(path)
            path.write_text('[{"full_name": "x"}]')
            with self.assertRaisesRegex(module.DiscoveryError, 'lacks a name'):
                module.load_repositories(path)


if __name__ == '__main__':
    unittest.main()
