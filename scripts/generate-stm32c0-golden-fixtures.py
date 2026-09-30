#!/usr/bin/env python3
"""Build deterministic original Cortex-M0+ fixtures for selected STM32C0 parts."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'fixtures/generators/stm32c0-minimal'
OUTPUT = ROOT / 'src/test/resources/fixtures/stm32c0'
ORACLES = ROOT / 'src/test/resources/oracles/stm32c0'
# Exact memory values are drawn from the reviewed catalog. Each Apache-2.0
# CMSIS header independently attests the two base addresses.
PARTS = {
    'STM32C051C8T6': (64, 12, 'stm32c051xx.h',
                       '7747e558cae5d8ff58d36f1a040c62041cd2e4698128bbefc095b7e2b908920b'),
    'STM32C071RBT6': (128, 24, 'stm32c071xx.h',
                       'aac35ab1388358a7c45e96c0e7e2f2febb96897f611871d27d6acd26e7f75544'),
    'STM32C092RCT6': (256, 30, 'stm32c092xx.h',
                       'ef7acde8a1dbe4e404e80d99ed139dee461e5e97dff8c8c060e09c07c917520f'),
}


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout


def sha(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def build_one(folder, part, flash_kib, ram_kib, header_name, header_sha):
    linker = folder / 'linker.ld'
    linker.write_text((SOURCE / 'linker.ld.in').read_text().replace('@FLASH_KIB@',
                                                              str(flash_kib)))
    obj = folder / 'startup.o'
    elf = folder / (part + '.elf')
    binary = folder / (part + '.bin')
    ihex = folder / (part + '.hex')
    stack_top = 0x20000000 + ram_kib * 1024
    run('arm-none-eabi-gcc', '-c', '-x', 'assembler-with-cpp',
        '-mcpu=cortex-m0plus', '-mthumb', '-DSTACK_TOP=' + hex(stack_top),
        '-DPART_STRING="' + part + '"', str(SOURCE / 'startup.S'), '-o', str(obj))
    run('arm-none-eabi-gcc', '-nostdlib', '-mcpu=cortex-m0plus', '-mthumb',
        '-Wl,--build-id=none', '-Wl,--no-undefined', '-T', str(linker),
        str(obj), '-o', str(elf))
    run('arm-none-eabi-objcopy', '-O', 'binary', str(elf), str(binary))
    run('arm-none-eabi-objcopy', '-O', 'ihex', str(elf), str(ihex))
    header = run('arm-none-eabi-readelf', '--file-header', str(elf))
    segments = run('arm-none-eabi-readelf', '--program-headers', str(elf))
    if ('Machine:                           ARM' not in header or
            '0x8000101' not in header and '0x08000101' not in header):
        raise RuntimeError('Cortex-M0+ ELF machine/entry mismatch')
    files = {ext: (folder / (part + '.' + ext)).read_bytes()
             for ext in ('elf', 'hex', 'bin')}
    oracle = canonical({'part': part, 'architecture': 'ARM Cortex-M0+',
                        'flashBase': '0x08000000', 'flashKiB': flash_kib,
                        'ramBase': '0x20000000', 'ramKiB': ram_kib,
                        'initialSp': f'0x{stack_top:08x}', 'resetVector': '0x08000101',
                        'elfMachine': 'ARM', 'elfHeader': header,
                        'elfProgramHeaders': segments,
                        'sourceProvenance': {
                            'name': 'ST ' + part + ' CMSIS device header',
                            'distribution': 'STM32Cube_FW_C0_V1.4.0',
                            'path': 'Drivers/CMSIS/Device/ST/STM32C0xx/Include/' + header_name,
                            'sha256': header_sha, 'license': 'Apache-2.0',
                            'facts': ['FLASH_BASE', 'SRAM_BASE']},
                        'artifactSha256': {ext: sha(data) for ext, data in files.items()}})
    return files, oracle


def build(folder):
    result = {}
    for part, values in PARTS.items():
        work = folder / part
        work.mkdir()
        result[part] = build_one(work, part, *values)
    return result


def main():
    with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
        one, two = build(Path(first)), build(Path(second))
        if one != two:
            raise RuntimeError('C0 fixtures are not byte reproducible')
    OUTPUT.mkdir(parents=True, exist_ok=True)
    ORACLES.mkdir(parents=True, exist_ok=True)
    revision = sha((SOURCE / 'startup.S').read_bytes() +
                   (SOURCE / 'linker.ld.in').read_bytes() + Path(__file__).read_bytes())
    version = (run('arm-none-eabi-gcc', '--version').splitlines()[0] + '; ' +
               run('arm-none-eabi-objcopy', '--version').splitlines()[0])
    for part, (files, oracle) in one.items():
        oracle_path = ORACLES / (part + '.json')
        oracle_path.write_bytes(oracle)
        for ext, data in files.items():
            path = OUTPUT / (part + '.' + ext)
            path.write_bytes(data)
            manifest = {
            'fixtureId': 'stm32c0.t033.' + part.lower() + '.' + ext,
            'sha256': sha(data), 'target': part, 'device': part,
            'inputFormat': {'elf': 'ELF32 ARM', 'hex': 'Intel HEX',
                            'bin': 'raw binary'}[ext],
            'origin': 'Generated from repository-authored freestanding Cortex-M0+ assembly/linker source',
            'license': 'Apache-2.0', 'redistributionStatus': 'REDISTRIBUTABLE',
            'generatorRevision': 'sha256:' + revision,
            'generationCommand': 'python3 scripts/generate-stm32c0-golden-fixtures.py',
            'toolchain': version,
            'sourceProvenance': json.loads(oracle)['sourceProvenance'],
            'oracleCommands': ['arm-none-eabi-readelf --file-header --program-headers <ELF>',
                               'arm-none-eabi-objcopy -O binary <ELF> <BIN>',
                               'arm-none-eabi-objcopy -O ihex <ELF> <HEX>'],
            'expectedSnapshot': str(oracle_path.relative_to(ROOT)),
            'requirements': ['T033', 'STM-001', 'STM-002', 'STM-004']}
            path.with_name(path.name + '.manifest.json').write_bytes(canonical(manifest))
    print('Generated 3 exact STM32C0 ELF/HEX/BIN sets twice, byte-identical')


if __name__ == '__main__':
    try:
        main()
    except (OSError, subprocess.CalledProcessError, RuntimeError) as exc:
        print('STM32C0 fixture generation: ' + str(exc), file=sys.stderr)
        raise SystemExit(1)
