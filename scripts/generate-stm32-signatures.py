#!/usr/bin/env python3
"""Generate the digest-pinned STM32 HAL/LL/CMSIS/FreeRTOS signature pack (T043).

Every signature is derived only from a pinned, permissively licensed
STMicroelectronics STM32Cube firmware package compiled with a pinned
``arm-none-eabi-gcc``. For each source file the generator compiles one object
with ``-ffunction-sections`` so every function occupies its own ``.text.<name>``
section, then records the raw instruction bytes with the bytes touched by an ELF
relocation masked out. Masked bytes are the address-dependent fields (calls and
absolute pointers) that vary between link layouts; the remaining bytes are a
stable fingerprint of that exact source/compiler/optimization combination.

No vendor source, header, object, or toolchain runtime is copied or bundled: the
pack contains only derived function names, source-relative provenance, and
masked byte patterns, and the toolchain identity and source digests are recorded
in a source-audit artifact. Nothing is inferred from a family or wildcard name;
a source file that cannot be compiled is skipped explicitly with a reason.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

SCHEMA_CONTENT = 'urn:embedra:schema:stm32-signature-pack:1'
SCHEMA_MANIFEST = 'urn:embedra:schema:pack-manifest:1'
PACK_ID = 'stm32.stm32f1.signatures'
PACK_VERSION = '1.0.0'
SERIES = 'STM32F1'
PACKAGE = 'STM32Cube_FW_F1_V1.8.7'
SOURCE_URL = 'https://github.com/STMicroelectronics/STM32CubeF1'
LICENSE = 'BSD-3-Clause AND Apache-2.0 AND MIT'
EXPECTED_ZIP_SHA256 = '1b5f99f86982efe5e4931063de4a0f0af80e38a05d4835b0b8f82aefad634b29'
TRANSFORMATION = (
    'Compiled pinned STM32Cube_FW_F1_V1.8.7 HAL/LL/CMSIS-device/FreeRTOS sources '
    'with the pinned arm-none-eabi-gcc at each recorded optimization using '
    '-ffunction-sections; per-function .text bytes are emitted with every byte '
    'touched by an ELF relocation masked out. Only derived names, source-relative '
    'provenance, and masked byte patterns are shipped; no source, object, or '
    'toolchain runtime is redistributed.')

MIN_PATTERN_BYTES = 8
MIN_SIGNIFICANT_BYTES = 8
OPTIMIZATIONS = ('-Os', '-O2')

DEFINES = ('STM32F103xB', 'USE_HAL_DRIVER', 'USE_FULL_LL_DRIVER')
BASE_FLAGS = (
    '-mcpu=cortex-m3', '-mthumb', '-ffunction-sections', '-fdata-sections',
    '-ffreestanding', '-fno-common', '-fno-stack-protector',
    '-fno-asynchronous-unwind-tables', '-fno-unwind-tables')

HAL_INC = 'Drivers/STM32F1xx_HAL_Driver/Inc'
CMSIS_DEVICE_INC = 'Drivers/CMSIS/Device/ST/STM32F1xx/Include'
CMSIS_CORE_INC = 'Drivers/CMSIS/Include'
HAL_SRC = 'Drivers/STM32F1xx_HAL_Driver/Src'
HAL_CONF = 'Projects/STM32F103RB-Nucleo/Templates/Inc/stm32f1xx_hal_conf.h'
SYSTEM_SRC = 'Projects/STM32F103RB-Nucleo/Templates/Src/system_stm32f1xx.c'
FREERTOS_INC = 'Middlewares/Third_Party/FreeRTOS/Source/include'
FREERTOS_PORT = 'Middlewares/Third_Party/FreeRTOS/Source/portable/GCC/ARM_CM3'
FREERTOS_CONF = ('Projects/STM32F103RB-Nucleo/Applications/FreeRTOS/'
                 'FreeRTOS_ThreadCreation/Inc/FreeRTOSConfig.h')

# (component, library, license, glob-relative-to-source-root, exclude-substrings)
COMPONENTS = (
    ('stm32f1xx-hal', 'stm32f1xx-hal', 'BSD-3-Clause', 'srcs',
     ('template',)),
    ('stm32f1xx-ll', 'stm32f1xx-ll', 'BSD-3-Clause', 'll', ()),
    ('cmsis-device', 'cmsis-device', 'Apache-2.0', 'cmsis', ()),
    ('freertos-kernel', 'freertos-kernel', 'MIT', 'freertos', ()),
    ('freertos-port', 'freertos-port', 'MIT', 'freertos-port', ()),
)


class SignatureError(ValueError):
    pass


def canonical(value) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(',', ':'),
                       ensure_ascii=False) + '\n').encode('utf-8')


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256(path.read_bytes())


def read_c_string(blob: bytes, offset: int) -> str:
    end = blob.find(b'\0', offset)
    if end < 0:
        end = len(blob)
    return blob[offset:end].decode('utf-8', 'replace')


def compiler_identity(gcc: str) -> str:
    result = subprocess.run([gcc, '--version'], capture_output=True, text=True)
    if result.returncode != 0:
        raise SignatureError('the pinned compiler is unavailable')
    return result.stdout.splitlines()[0].strip()


def parse_elf(data: bytes):
    """Return (sections, relocations_by_target_section_name).

    Each section is a dict with name/type/offset/size/link/info. Relocations map
    a target section name to a list of (offset, type) tuples.
    """
    if len(data) < 0x34 or data[:4] != b'\x7fELF' or data[4] != 1 or data[5] != 1:
        raise SignatureError('object is not a little-endian ELF32 file')
    (shoff,) = struct.unpack_from('<I', data, 0x20)
    (shentsize,) = struct.unpack_from('<H', data, 0x2E)
    (shnum,) = struct.unpack_from('<H', data, 0x30)
    (shstrndx,) = struct.unpack_from('<H', data, 0x32)
    if shentsize < 40 or shnum == 0 or shoff == 0:
        raise SignatureError('object has no usable section headers')
    sections = []
    for index in range(shnum):
        base = shoff + index * shentsize
        if base + 40 > len(data):
            raise SignatureError('object section header table is truncated')
        (nameoff, stype, _flags, _addr, offset, size, link, info, _align,
         _entsize) = struct.unpack_from('<IIIIIIIIII', data, base)
        sections.append({'index': index, 'nameoff': nameoff, 'type': stype,
                         'offset': offset, 'size': size, 'link': link,
                         'info': info})
    if shstrndx >= len(sections):
        raise SignatureError('object section-name table is missing')
    strings = sections[shstrndx]
    blob = data[strings['offset']:strings['offset'] + strings['size']]
    for section in sections:
        section['name'] = read_c_string(blob, section['nameoff'])
    relocations = {}
    for section in sections:
        if section['type'] not in (9, 4):  # SHT_REL / SHT_RELA
            continue
        entry = 16 if section['type'] == 4 else 8
        count = section['size'] // entry
        target = sections[section['info']]['name'] if section['info'] < len(sections) else ''
        entries = relocations.setdefault(target, [])
        for index in range(count):
            base = section['offset'] + index * entry
            if base + entry > len(data):
                raise SignatureError('object relocation table is truncated')
            (roffset,) = struct.unpack_from('<I', data, base)
            (rinfo,) = struct.unpack_from('<I', data, base + 4)
            entries.append((roffset, rinfo & 0xFF))
    return sections, relocations


def extract_functions(object_path: Path):
    """Return a list of (section-name, function-name, pattern, mask)."""
    data = object_path.read_bytes()
    sections, relocations = parse_elf(data)
    results = []
    for section in sections:
        name = section['name']
        if section['type'] != 1 or not name.startswith('.text.') or section['size'] == 0:
            continue
        start = section['offset']
        size = section['size']
        if start + size > len(data):
            raise SignatureError('object .text section is truncated')
        pattern = bytearray(data[start:start + size])
        mask = bytearray(b'\xff') * size
        for offset, _rtype in relocations.get(name, ()):
            for index in range(offset, min(offset + 4, size)):
                mask[index] = 0
        function = name[len('.text.'):]
        results.append((name, function, bytes(pattern), bytes(mask)))
    results.sort(key=lambda item: item[1])
    return results


def source_inventory(cube_root: Path):
    sources = cube_root / HAL_SRC
    hal = sorted(p for p in sources.glob('stm32f1xx_hal*.c')
                 if 'template' not in p.name)
    ll = sorted(sources.glob('stm32f1xx_ll_*.c'))
    cmsis = [cube_root / SYSTEM_SRC]
    freertos = sorted(
        (cube_root / 'Middlewares/Third_Party/FreeRTOS/Source').glob('*.c'))
    freertos_port = [cube_root / FREERTOS_PORT / 'port.c']
    return {
        'stm32f1xx-hal': hal,
        'stm32f1xx-ll': ll,
        'cmsis-device': cmsis,
        'freertos-kernel': freertos,
        'freertos-port': freertos_port,
    }


def include_flags(cube_root: Path):
    return [
        '-I' + str(cube_root / 'Projects/STM32F103RB-Nucleo/Templates/Inc'),
        '-I' + str(cube_root / HAL_INC),
        '-I' + str(cube_root / CMSIS_DEVICE_INC),
        '-I' + str(cube_root / CMSIS_CORE_INC),
        '-I' + str(cube_root / 'Projects/STM32F103RB-Nucleo/Applications/FreeRTOS/'
                             'FreeRTOS_ThreadCreation/Inc'),
        '-I' + str(cube_root / FREERTOS_INC),
        '-I' + str(cube_root / FREERTOS_PORT),
    ]


def optimizer_slug(optimization: str) -> str:
    return optimization.lstrip('-').replace('/', '_')


def sanitize(value: str) -> str:
    return ''.join(ch if ch.isalnum() or ch in '._-' else '_' for ch in value)


def compile_object(gcc: str, source: Path, output: Path, optimization: str,
                   cube_root: Path):
    command = [gcc, '-c', optimization, *BASE_FLAGS,
               *[f'-D{define}' for define in DEFINES],
               *include_flags(cube_root), str(source), '-o', str(output)]
    result = subprocess.run(command, capture_output=True, text=True,
                            env={**os.environ, 'LC_ALL': 'C'})
    if result.returncode != 0:
        return result.stderr.strip().splitlines()[-1] if result.stderr.strip() else 'compile failed'
    return None


def build_signatures(gcc: str, cube_root: Path, token):
    compiler = compiler_identity(gcc)
    inventory = source_inventory(cube_root)
    signatures = []
    components = []
    skipped = []
    low_specificity = 0
    with tempfile.TemporaryDirectory(prefix='embedra-stm32-signatures-') as temp:
        work = Path(temp)
        for component, library, license_name, _kind, _exclude in COMPONENTS:
            files = inventory[component]
            if not files:
                raise SignatureError(f'{component}: no pinned source files found')
            file_records = []
            for source in files:
                token()
                relative = source.relative_to(cube_root).as_posix()
                file_records.append({'path': relative, 'sha256': sha256_file(source)})
                for optimization in OPTIMIZATIONS:
                    obj = work / (sanitize(relative) + optimizer_slug(optimization) + '.o')
                    failure = compile_object(gcc, source, obj, optimization, cube_root)
                    if failure is not None:
                        skipped.append({'path': relative, 'optimization': optimization,
                                        'reason': f'COMPILE_FAILED: {failure}'})
                        continue
                    for _section, function, pattern, mask in extract_functions(obj):
                        if len(pattern) < MIN_PATTERN_BYTES:
                            low_specificity += 1
                            continue
                        if sum(1 for value in mask if value == 0xFF) < MIN_SIGNIFICANT_BYTES:
                            low_specificity += 1
                            continue
                        stem = sanitize(source.stem)
                        signature_id = '.'.join((
                            'stm32f1', sanitize(component), stem,
                            sanitize(function), optimizer_slug(optimization)))
                        signatures.append({
                            'signatureId': signature_id,
                            'library': library,
                            'component': component,
                            'functionName': function,
                            'family': SERIES,
                            'compiler': compiler,
                            'optimization': optimization,
                            'sourceFile': relative,
                            'sourceSha256': file_records[-1]['sha256'],
                            'pattern': pattern.hex(),
                            'mask': mask.hex(),
                        })
            components.append({'name': component, 'license': license_name,
                               'files': file_records})
    signatures.sort(key=lambda item: item['signatureId'])
    identifiers = [item['signatureId'] for item in signatures]
    if len(set(identifiers)) != len(identifiers):
        raise SignatureError('generated signature identifiers are not unique')
    if not signatures:
        raise SignatureError('no signatures were generated')
    return compiler, signatures, components, skipped, low_specificity


def content_digest(files):
    digest = hashlib.sha256()
    for entry in sorted(files, key=lambda item: item['path']):
        descriptor = (entry['path'] + '\0' + str(entry['size']) + '\0'
                      + entry['sha256'] + '\n')
        digest.update(descriptor.encode('utf-8'))
    return digest.hexdigest()


def build_pack(gcc: str, cube_root: Path, zip_sha256: str, token):
    compiler, signatures, components, skipped, low_specificity = build_signatures(
        gcc, cube_root, token)
    content = {
        '$schema': SCHEMA_CONTENT,
        'sourcePackage': PACKAGE,
        'series': SERIES,
        'signatures': signatures,
    }
    signatures_bytes = canonical(content)
    signatures_sha = sha256(signatures_bytes)
    files = [{'path': 'signatures.json', 'size': len(signatures_bytes),
              'sha256': signatures_sha}]
    manifest = {
        'schemaId': SCHEMA_MANIFEST,
        'packId': PACK_ID,
        'version': PACK_VERSION,
        'contentDigest': content_digest(files),
        'supportedDevices': [SERIES],
        'provenance': {
            'source': SOURCE_URL,
            'revision': PACKAGE,
            'license': LICENSE,
            'transformation': TRANSFORMATION,
            'redistribution': 'ALLOWED',
        },
        'files': files,
    }
    audit = {
        '$schema': 'urn:embedra:schema:stm32-signature-source-audit:1',
        'package': PACKAGE,
        'sourceUrl': SOURCE_URL,
        'zipSha256': zip_sha256,
        'compiler': compiler,
        'optimizations': list(OPTIMIZATIONS),
        'defines': list(DEFINES),
        'flags': list(BASE_FLAGS),
        'components': components,
        'configFiles': [
            {'path': HAL_CONF, 'sha256': sha256_file(cube_root / HAL_CONF)},
            {'path': FREERTOS_CONF,
             'sha256': sha256_file(cube_root / FREERTOS_CONF)},
        ],
        'skipped': skipped,
        'lowSpecificityFunctions': low_specificity,
        'generated': {
            'packId': PACK_ID,
            'version': PACK_VERSION,
            'signatures': len(signatures),
            'signaturesSha256': signatures_sha,
            'contentDigest': manifest['contentDigest'],
        },
    }
    return canonical(manifest), signatures_bytes, canonical(audit)


def resolve_zip_sha256(cube_zip: Path | None) -> str:
    if cube_zip is None:
        return EXPECTED_ZIP_SHA256
    if not cube_zip.is_file():
        raise SignatureError('the pinned STM32Cube archive is missing')
    observed = sha256_file(cube_zip)
    if observed != EXPECTED_ZIP_SHA256:
        raise SignatureError('the STM32Cube archive digest does not match the pin')
    return observed


def run(mode: str, gcc: str, cube_root: Path, cube_zip: Path | None,
        pack_dir: Path, audit_path: Path) -> int:
    token = lambda: None
    manifest_bytes, signatures_bytes, audit_bytes = build_pack(
        gcc, cube_root, resolve_zip_sha256(cube_zip), token)
    if mode == 'generate':
        pack_dir.mkdir(parents=True, exist_ok=True)
        (pack_dir / 'pack.json').write_bytes(manifest_bytes)
        (pack_dir / 'signatures.json').write_bytes(signatures_bytes)
        audit_path.parent.mkdir(parents=True, exist_ok=True)
        audit_path.write_bytes(audit_bytes)
        return 0
    committed_manifest = (pack_dir / 'pack.json').read_bytes()
    committed_signatures = (pack_dir / 'signatures.json').read_bytes()
    committed_audit = audit_path.read_bytes()
    if (committed_manifest != manifest_bytes
            or committed_signatures != signatures_bytes
            or committed_audit != audit_bytes):
        raise SignatureError('committed signature pack differs from regeneration')
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['generate', 'check'])
    parser.add_argument('--cube-root', type=Path, required=True)
    parser.add_argument('--cube-zip', type=Path)
    parser.add_argument('--gcc', default='arm-none-eabi-gcc')
    parser.add_argument('--pack-dir', type=Path, required=True)
    parser.add_argument('--audit', type=Path, required=True)
    args = parser.parse_args()
    try:
        return run(args.mode, args.gcc, args.cube_root, args.cube_zip,
                   args.pack_dir, args.audit)
    except (SignatureError, OSError, KeyError, TypeError, ValueError) as exc:
        print(f'STM32 signatures: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
