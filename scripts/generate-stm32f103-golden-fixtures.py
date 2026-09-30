#!/usr/bin/env python3
"""Build deterministic, repository-authored Cortex-M3 STM32F103 fixtures."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'fixtures/generators/stm32f103-minimal'
OUTPUT = ROOT / 'src/test/resources/fixtures/stm32f103'
ORACLES = ROOT / 'src/test/resources/oracles/stm32f103'
PARTS = {'STM32F103C8T6': 64, 'STM32F103CBT6': 128,
         'STM32F103RBT6': 128}
PREFIX = 'arm-none-eabi-'


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def build(folder):
    result = {}
    template = (SOURCE / 'linker.ld.in').read_text()
    source_hash = digest((SOURCE / 'startup.S').read_bytes() +
                         (SOURCE / 'linker.ld.in').read_bytes() +
                         Path(__file__).read_bytes())
    version = (run(PREFIX + 'gcc', '--version').splitlines()[0] + '; ' +
               run(PREFIX + 'objcopy', '--version').splitlines()[0])
    for part, flash_kib in PARTS.items():
        work = folder / part
        work.mkdir()
        linker = work / 'linker.ld'
        linker.write_text(template.replace('@FLASH_KIB@', str(flash_kib)))
        obj = work / 'startup.o'
        elf = work / (part + '.elf')
        binary = work / (part + '.bin')
        ihex = work / (part + '.hex')
        run(PREFIX + 'gcc', '-c', '-x', 'assembler-with-cpp',
            '-mcpu=cortex-m3', '-mthumb', '-DPART_STRING="' + part + '"',
            str(SOURCE / 'startup.S'), '-o', str(obj))
        run(PREFIX + 'gcc', '-nostdlib', '-mcpu=cortex-m3', '-mthumb',
            '-Wl,--build-id=none', '-Wl,--no-undefined', '-T', str(linker),
            str(obj), '-o', str(elf))
        run(PREFIX + 'objcopy', '-O', 'binary', str(elf), str(binary))
        run(PREFIX + 'objcopy', '-O', 'ihex', str(elf), str(ihex))
        header = run(PREFIX + 'readelf', '--file-header', str(elf))
        segments = run(PREFIX + 'readelf', '--program-headers', str(elf))
        if 'Machine:                           ARM' not in header:
            raise RuntimeError('ELF machine is not ARM')
        if '0x8000101' not in header and '0x08000101' not in header:
            raise RuntimeError('ELF reset entry is not in flash text: ' +
                               next((line for line in header.splitlines()
                                     if 'Entry point address' in line), 'missing entry'))
        oracle = {'part': part, 'architecture': 'ARM Cortex-M3',
                  'flashBase': '0x08000000', 'flashKiB': flash_kib,
                  'ramKiB': 20, 'initialSp': '0x20005000',
                  'resetVector': '0x08000101',
                  'elfMachine': 'ARM', 'elfHeader': header,
                  'elfProgramHeaders': segments,
                  'artifactSha256': {ext: digest((work / (part + '.' + ext)).read_bytes())
                                     for ext in ('elf', 'hex', 'bin')}}
        result[part] = {'files': {ext: (work / (part + '.' + ext)).read_bytes()
                                  for ext in ('elf', 'hex', 'bin')},
                        'oracle': canonical(oracle), 'sourceHash': source_hash,
                        'toolchain': version}
    return result


def main():
    with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
        one, two = build(Path(first)), build(Path(second))
        for part in PARTS:
            if one[part]['files'] != two[part]['files'] or one[part]['oracle'] != two[part]['oracle']:
                raise RuntimeError('non-reproducible fixture: ' + part)
        OUTPUT.mkdir(parents=True, exist_ok=True)
        ORACLES.mkdir(parents=True, exist_ok=True)
        for part, info in one.items():
            oracle_path = ORACLES / (part + '.json')
            oracle_path.write_bytes(info['oracle'])
            for ext, data in info['files'].items():
                path = OUTPUT / (part + '.' + ext)
                path.write_bytes(data)
                manifest = {
                    'fixtureId': 'stm32f103.t033.' + part.lower() + '.' + ext,
                    'sha256': digest(data), 'target': part, 'device': part,
                    'inputFormat': {'elf': 'ELF32 ARM', 'hex': 'Intel HEX',
                                    'bin': 'raw binary'}[ext],
                    'origin': 'Generated from repository-authored freestanding assembly and linker source',
                    'license': 'Apache-2.0', 'redistributionStatus': 'REDISTRIBUTABLE',
                    'generatorRevision': 'sha256:' + info['sourceHash'],
                    'generationCommand': 'python3 scripts/generate-stm32f103-golden-fixtures.py',
                    'toolchain': info['toolchain'],
                    'oracleCommands': ['arm-none-eabi-readelf --file-header --program-headers <ELF>',
                                       'arm-none-eabi-objcopy -O binary <ELF> <BIN>',
                                       'arm-none-eabi-objcopy -O ihex <ELF> <HEX>'],
                    'expectedSnapshot': str(oracle_path.relative_to(ROOT)),
                    'requirements': ['T033', 'STM-001', 'STM-002', 'STM-003', 'STM-004']}
                path.with_name(path.name + '.manifest.json').write_bytes(canonical(manifest))
    print('Generated 3 exact-part STM32F103 ELF/HEX/BIN fixture sets twice, byte-identical')


if __name__ == '__main__':
    try:
        main()
    except (OSError, subprocess.CalledProcessError, RuntimeError) as exc:
        print('STM32F103 fixture generation: ' + str(exc), file=sys.stderr)
        raise SystemExit(1)
