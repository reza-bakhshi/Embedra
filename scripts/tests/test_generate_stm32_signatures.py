"""STM32 signature packs: determinism, provenance, and fail-closed contracts.

The committed pack is validated unconditionally. Regeneration against the pinned
redistributable STM32Cube source and the pinned toolchain runs only when
``EMBEDRA_STM32CUBE_ROOT`` is set; otherwise the check is skipped explicitly and
the skip is recorded.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'scripts' / 'generate-stm32-signatures.py'
SPEC = importlib.util.spec_from_file_location('stm32_signatures', SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

PACK = ROOT / 'packs' / 'stm32.stm32f1.signatures' / '1.0.0'
AUDIT = ROOT / '.embedra' / 'evidence' / 'tasks' / 'T043-signature-source-audit.json'
SIGNATURE_FIELDS = {
    'signatureId', 'library', 'component', 'functionName', 'family', 'compiler',
    'optimization', 'sourceFile', 'sourceSha256', 'pattern', 'mask',
}
HEX = re.compile(r'^[0-9a-f]+$')


def cube_root():
    value = os.environ.get('EMBEDRA_STM32CUBE_ROOT')
    return Path(value) if value else None


def load_json(path):
    return json.loads(path.read_bytes())


class CommittedPackTests(unittest.TestCase):
    def setUp(self):
        self.manifest = load_json(PACK / 'pack.json')
        self.content = load_json(PACK / 'signatures.json')
        self.audit = load_json(AUDIT)

    def test_manifest_pins_identity_and_content_digest(self):
        self.assertEqual(MODULE.SCHEMA_MANIFEST, self.manifest['schemaId'])
        self.assertEqual(MODULE.PACK_ID, self.manifest['packId'])
        self.assertEqual(MODULE.PACK_VERSION, self.manifest['version'])
        self.assertEqual([MODULE.SERIES], self.manifest['supportedDevices'])
        provenance = self.manifest['provenance']
        self.assertEqual(MODULE.SOURCE_URL, provenance['source'])
        self.assertEqual(MODULE.PACKAGE, provenance['revision'])
        self.assertEqual(MODULE.LICENSE, provenance['license'])
        self.assertEqual('ALLOWED', provenance['redistribution'])
        files = self.manifest['files']
        self.assertEqual(1, len(files))
        raw = (PACK / files[0]['path']).read_bytes()
        self.assertEqual(len(raw), files[0]['size'])
        self.assertEqual(hashlib.sha256(raw).hexdigest(), files[0]['sha256'])
        self.assertEqual(MODULE.content_digest(files), self.manifest['contentDigest'])

    def test_content_is_closed_and_well_formed(self):
        self.assertEqual(MODULE.SCHEMA_CONTENT, self.content['$schema'])
        self.assertEqual(MODULE.SERIES, self.content['series'])
        self.assertEqual(MODULE.PACKAGE, self.content['sourcePackage'])
        signatures = self.content['signatures']
        self.assertEqual(1543, len(signatures))
        identifiers = [item['signatureId'] for item in signatures]
        self.assertEqual(sorted(identifiers), identifiers)
        self.assertEqual(len(set(identifiers)), len(identifiers))
        for item in signatures:
            self.assertEqual(SIGNATURE_FIELDS, set(item))
            self.assertEqual(MODULE.SERIES, item['family'])
            self.assertIn(item['optimization'], self.audit['optimizations'])
            self.assertEqual(self.audit['compiler'], item['compiler'])
            self.assertRegex(item['sourceSha256'], r'^[0-9a-f]{64}$')
            pattern, mask = item['pattern'], item['mask']
            self.assertRegex(pattern, HEX)
            self.assertRegex(mask, HEX)
            self.assertEqual(len(pattern), len(mask))
            self.assertGreaterEqual(len(pattern) // 2, MODULE.MIN_PATTERN_BYTES)
            for index in range(0, len(mask), 2):
                self.assertIn(mask[index:index + 2], ('00', 'ff'))
            self.assertTrue(any(mask[index:index + 2] == 'ff'
                                for index in range(0, len(mask), 2)))

    def test_every_signature_cites_an_audited_source_file(self):
        hashes = {}
        for component in self.audit['components']:
            for entry in component['files']:
                hashes[entry['path']] = entry['sha256']
        for item in self.content['signatures']:
            self.assertIn(item['sourceFile'], hashes)
            self.assertEqual(hashes[item['sourceFile']], item['sourceSha256'])

    def test_audit_pins_the_redistributable_source_and_toolchain(self):
        self.assertEqual(MODULE.EXPECTED_ZIP_SHA256, self.audit['zipSha256'])
        self.assertEqual(MODULE.PACKAGE, self.audit['package'])
        self.assertTrue(self.audit['compiler'])
        self.assertEqual(list(MODULE.OPTIMIZATIONS), self.audit['optimizations'])
        licenses = {component['license'] for component in self.audit['components']}
        self.assertTrue(licenses <= {'BSD-3-Clause', 'Apache-2.0', 'MIT'})
        self.assertEqual([], self.audit['skipped'])
        self.assertEqual(self.manifest['contentDigest'],
                         self.audit['generated']['contentDigest'])
        self.assertEqual(len(self.content['signatures']),
                         self.audit['generated']['signatures'])


class GeneratorUnitTests(unittest.TestCase):
    def test_canonical_json_is_sorted_and_newline_terminated(self):
        self.assertEqual(b'{"a":1,"b":2}\n', MODULE.canonical({'b': 2, 'a': 1}))

    def test_content_digest_matches_java_descriptor_formula(self):
        files = [{'path': 'signatures.json', 'size': 3, 'sha256': 'a' * 64}]
        expected = hashlib.sha256(
            ('signatures.json\0' + '3' + '\0' + 'a' * 64 + '\n').encode()).hexdigest()
        self.assertEqual(expected, MODULE.content_digest(files))

    def test_non_elf_input_fails_closed(self):
        with self.assertRaises(MODULE.SignatureError):
            MODULE.parse_elf(b'not an elf object')

    def test_zip_pin_rejects_a_mismatched_archive(self):
        with tempfile.TemporaryDirectory() as folder:
            archive = Path(folder) / 'cube.zip'
            archive.write_bytes(b'wrong')
            with self.assertRaises(MODULE.SignatureError):
                MODULE.resolve_zip_sha256(archive)

    def test_optimizer_slug_is_stable(self):
        self.assertEqual('Os', MODULE.optimizer_slug('-Os'))
        self.assertEqual('O2', MODULE.optimizer_slug('-O2'))


class RegenerationTests(unittest.TestCase):
    @unittest.skipUnless(cube_root() is not None,
                         'pinned STM32Cube F1 source root is unavailable')
    def test_regeneration_matches_committed_pack(self):
        command = [sys.executable, str(SCRIPT), 'check',
                   '--cube-root', str(cube_root()),
                   '--pack-dir', str(PACK), '--audit', str(AUDIT)]
        archive = os.environ.get('EMBEDRA_STM32CUBE_ZIP')
        if archive:
            command += ['--cube-zip', archive]
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(0, result.returncode, result.stderr)

    @unittest.skipUnless(cube_root() is not None,
                         'pinned STM32Cube F1 source root is unavailable')
    def test_regeneration_rejects_a_tampered_copy(self):
        with tempfile.TemporaryDirectory() as folder:
            pack = Path(folder) / 'pack'
            audit = Path(folder) / 'audit.json'
            shutil.copytree(PACK, pack)
            shutil.copy(AUDIT, audit)
            data = json.loads((pack / 'signatures.json').read_bytes())
            data['signatures'] = data['signatures'][:-1]
            (pack / 'signatures.json').write_bytes(MODULE.canonical(data))
            command = [sys.executable, str(SCRIPT), 'check',
                       '--cube-root', str(cube_root()), '--pack-dir', str(pack),
                       '--audit', str(audit)]
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertNotEqual(0, result.returncode)


if __name__ == '__main__':
    unittest.main()
