#!/usr/bin/env python3
"""Write provenance manifests for the committed T026A Function ID fixtures.

Reads the digest oracle produced by scripts/generate-esp32s3-fid-ref.sh and
writes one sidecar manifest per committed fixture binary. Values are
content-addressed; no host paths are recorded.
"""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / 'src/test/resources/fixtures/esp32s3/fid'
DIGESTS = ROOT / ('src/test/resources/oracles/esp32s3/fid/'
                  'esp32s3-fid-reference-digests.json')
GENERATOR = ROOT / 'scripts/generate-esp32s3-fid-ref.sh'

TOOLCHAIN = ('Espressif xtensa-esp-elf esp-15.2.0_20251204 (gcc 15.2.0, '
             'binutils 2.45); ESP-IDF v6.0 662a3be354759d9487bf4b1a629fadb766cb1800; '
             'esptool 5.4.0')
LICENSE = ('Apache-2.0 sources and audited ESP-IDF components; linked toolchain '
           'runtime conveyed under its runtime exception (see THIRD_PARTY_NOTICES.md)')
EXPECTED = str(DIGESTS.relative_to(ROOT))
REQUIREMENTS = ['T026A', 'ESP-021']


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def manifest(fixture_id: str, input_format: str, origin: str, target: Path) -> dict:
    return {
        'fixtureId': fixture_id,
        'sha256': sha(target),
        'target': 'ESP32-S3',
        'device': 'ESP32-S3 (chip ID 9; no package or embedded-memory variant claim)',
        'inputFormat': input_format,
        'origin': origin,
        'license': LICENSE,
        'redistributionStatus': 'REDISTRIBUTABLE',
        'generatorRevision': 'sha256:' + sha(GENERATOR),
        'generationCommand': 'source the ESP-IDF v6.0 export environment and run '
                             'scripts/generate-esp32s3-fid-ref.sh (Ghidra 12.1.3 '
                             'required for the database step only)',
        'toolchain': TOOLCHAIN,
        'oracleCommands': [
            'esptool --chip esp32s3 image-info <fixture>',
            'xtensa-esp32s3-elf-nm --defined-only --print-size <fixture>',
        ],
        'expectedSnapshot': EXPECTED,
        'requirements': REQUIREMENTS,
    }


ELF_ORIGIN = ('Built by scripts/generate-esp32s3-fid-ref.sh from repository-original '
              'ESP-IDF application sources at the pinned revision, then made '
              'path-independent with CONFIG_APP_REPRODUCIBLE_BUILD and objcopy '
              '--strip-debug (symbol table retained)')
BIN_ORIGIN = ('esptool elf2image of the committed debug-stripped reference ELF at '
              'the pinned revision; the application description embeds the ELF digest')

TARGETS = [
    ('embedra-fid-ref-app-a.elf', 'esp32s3.idf-v6.0.embedra-fid-ref-app-a-elf',
     'Symbolized Xtensa executable ELF (debug-stripped)', ELF_ORIGIN),
    ('embedra-fid-ref-app-a.bin', 'esp32s3.idf-v6.0.embedra-fid-ref-app-a-image',
     'Espressif application image v1 (inherently stripped)', BIN_ORIGIN),
    ('embedra-fid-ref-app-a-o2.bin',
     'esp32s3.idf-v6.0.embedra-fid-ref-app-a-o2-image',
     'Espressif application image v1 (inherently stripped)', BIN_ORIGIN),
    ('embedra-fid-cross-app-b.bin', 'esp32s3.idf-v6.0.embedra-fid-cross-app-b-image',
     'Espressif application image v1 (inherently stripped)', BIN_ORIGIN),
]


def main() -> None:
    for name, fixture_id, input_format, origin in TARGETS:
        target = FIXTURES / name
        document = manifest(fixture_id, input_format, origin, target)
        sidecar = target.with_name(name + '.manifest.json')
        sidecar.write_text(json.dumps(document, indent=2) + '\n')
        print(f'wrote {sidecar.name} ({document["sha256"][:12]})')


if __name__ == '__main__':
    main()
