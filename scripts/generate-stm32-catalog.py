#!/usr/bin/env python3
"""Generate an offline STM32 catalog from ST's redistributable pin database.

This is deliberately a source-facts catalog. It does not infer orderable suffixes,
DBGMCU IDs, lifecycle, IRQ vectors, or SVD matches from family resemblance.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import xml.etree.ElementTree as ET

SCHEMA = 'urn:embedra:schema:stm32-source-catalog:1'
MAX_FILES = 5000
MAX_FILE_BYTES = 2_000_000
MAX_TOTAL_BYTES = 500_000_000
MAX_XML_DEPTH = 32
MAX_ELEMENTS = 20000
MAX_RECORDS = 5000
PIN_REVISION = '7d1f1514ed5583ec5007ad91236b4e1d377295b1'
PIN_URL = 'https://github.com/STMicroelectronics/STM32_open_pin_data'
PART_RE = re.compile(r'STM32[A-Za-z0-9()+-]+')


class CatalogError(ValueError):
    pass


def canonical(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=False,
                       separators=(',', ':')) + '\n').encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def local(tag):
    return tag.rsplit('}', 1)[-1]


def read_xml(path):
    if path.is_symlink() or not path.is_file():
        raise CatalogError(f'unsafe input: {path.name}')
    if path.stat().st_size > MAX_FILE_BYTES:
        raise CatalogError(f'oversized input: {path.name}')
    data = path.read_bytes()
    if b'<!DOCTYPE' in data.upper() or b'<!ENTITY' in data.upper():
        raise CatalogError(f'DTD/entity in {path.name}')
    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        raise CatalogError(f'malformed XML in {path.name}: {exc}') from exc
    stack = [(root, 1)]
    elements = 0
    while stack:
        element, depth = stack.pop()
        elements += 1
        if depth > MAX_XML_DEPTH or elements > MAX_ELEMENTS:
            raise CatalogError(f'XML complexity limit in {path.name}')
        stack.extend((child, depth + 1) for child in element)
    return root, digest(data), len(data)


def single_text(root, name):
    values = [(child.text or '').strip() for child in root if local(child.tag) == name]
    if len(values) != 1:
        raise CatalogError(f'expected one {name} for {root.get("RefName")}')
    return values[0]


def integer_values(root, name):
    values = [(child.text or '').strip() for child in root if local(child.tag) == name]
    if not values or len(values) > 16 or any(not re.fullmatch(r'[0-9]{1,8}', v) for v in values):
        raise CatalogError(f'invalid {name} for {root.get("RefName")}')
    return sorted(set(int(v) for v in values))


def record(root, path, sha):
    if local(root.tag) != 'Mcu':
        raise CatalogError(f'expected Mcu in {path.name}')
    ref = root.get('RefName', '')
    if ref != path.stem or not PART_RE.fullmatch(ref):
        raise CatalogError(f'invalid RefName in {path.name}')
    family = root.get('Family', '')
    package = root.get('Package', '')
    if not family.startswith('STM32') or not package or len(package) > 64:
        raise CatalogError(f'missing family/package in {path.name}')
    cores = [(child.text or '').strip().replace('Arm ', 'ARM ')
             for child in root if local(child.tag) == 'Core']
    if not cores or len(cores) > 8 or any(not re.fullmatch(r'ARM Cortex-[A-Z][0-9]+\+?', c) for c in cores):
        raise CatalogError(f'invalid execution topology in {path.name}')
    contexts = sorted({(child.get('Core'), child.get('Name'), child.get('Secure'))
                       for child in root if local(child.tag) == 'Context'
                       and child.get('Core') and child.get('Name')})
    ips = sorted({child.get('Name') for child in root if local(child.tag) == 'IP'
                  and child.get('Name')})
    flash = integer_values(root, 'Flash') if any(local(c.tag) == 'Flash' for c in root) else []
    ram = integer_values(root, 'Ram')
    if any(v > 65536 for v in flash + ram):
        raise CatalogError(f'implausible memory in {path.name}')
    return {
        'id': ref, 'identityKind': 'ST_REFERENCE_PATTERN' if ('(' in ref or 'x' in ref) else 'ST_REFERENCE',
        'family': family, 'line': root.get('Line', ''), 'package': package,
        'flashKiBValues': flash, 'ramKiBValues': ram,
        'processors': [{'index': i, 'core': core, 'role': 'APPLICATION' if 'Cortex-A' in core else 'MICROCONTROLLER'}
                       for i, core in enumerate(cores)],
        'executionContexts': [{'core': c, 'name': n, 'secure': s == 'true'} for c, n, s in contexts],
        'peripheralNames': ips,
        'securityEvidence': sorted({n for n in ips if any(token in n.upper() for token in
                             ('AES', 'HASH', 'CRYP', 'RNG', 'BSEC', 'GTZC', 'TZSC', 'PKA', 'HDP'))}),
        'lifecycle': 'UNKNOWN', 'deviceIds': [], 'interrupts': [],
        'svdTransformation': {'status': 'UNMAPPED', 'rule': 'REQUIRE_EXACT_CMSIS_DEVICE_MATCH'},
        'sourcePath': 'mcu/' + path.name, 'sourceSha256': sha,
    }


def generate(root_path, cancelled=lambda: False):
    mcu_dir = root_path / 'mcu'
    if root_path.is_symlink() or mcu_dir.is_symlink() or not mcu_dir.is_dir():
        raise CatalogError('unsafe or absent ST mcu directory')
    paths = sorted(mcu_dir.glob('STM32*.xml'), key=lambda p: p.name)
    if not paths or len(paths) > MAX_FILES:
        raise CatalogError('ST input count outside limit')
    total = 0
    records = []
    for path in paths:
        if cancelled():
            raise CatalogError('catalog generation cancelled')
        parsed, sha, size = read_xml(path)
        total += size
        if total > MAX_TOTAL_BYTES:
            raise CatalogError('ST input total exceeds byte limit')
        records.append(record(parsed, path, sha))
        if len(records) > MAX_RECORDS:
            raise CatalogError('catalog record limit')
    ids = [r['id'] for r in records]
    if len(ids) != len(set(ids)):
        raise CatalogError('duplicate ST references')
    records.sort(key=lambda r: r['id'])
    return {
        '$schema': SCHEMA, 'generator': 'embedra-stm32-catalog-v1',
        'sources': [{'identity': 'STMicroelectronics/STM32_open_pin_data',
                     'url': PIN_URL, 'revision': PIN_REVISION,
                     'license': 'BSD-3-Clause', 'redistribution': 'DERIVED_FACTS_ALLOWED',
                     'inputFiles': len(paths), 'inputBytes': total}],
        'records': records,
    }


def validate(catalog):
    if catalog.get('$schema') != SCHEMA or not isinstance(catalog.get('records'), list):
        raise CatalogError('invalid catalog schema')
    records = catalog['records']
    if not records or len(records) > MAX_RECORDS:
        raise CatalogError('invalid catalog record count')
    ids = [r['id'] for r in records]
    if ids != sorted(set(ids)):
        raise CatalogError('unsorted or duplicate records')
    for r in records:
        if not r['processors'] or any(v < 0 for v in r['flashKiBValues']) or not r['ramKiBValues'] or any(v <= 0 for v in r['ramKiBValues']):
            raise CatalogError(f'invalid structural facts for {r["id"]}')
        if not re.fullmatch(r'[0-9a-f]{64}', r['sourceSha256']):
            raise CatalogError(f'invalid source digest for {r["id"]}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['generate', 'check', 'drift'])
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--baseline', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.mode != 'generate' and args.baseline is None:
        parser.error('--baseline required for check/drift')
    if args.mode != 'check' and args.output is None:
        parser.error('--output required for generate/drift')
    try:
        revision = subprocess.check_output(
            ['git', '-C', str(args.source), 'rev-parse', 'HEAD'],
            stderr=subprocess.DEVNULL, text=True).strip()
        if args.mode != 'drift' and revision != PIN_REVISION:
            raise CatalogError('ST input revision does not match pinned revision')
        current = generate(args.source)
        current['sources'][0]['revision'] = revision
        validate(current)
        if args.mode == 'generate':
            args.output.write_bytes(canonical(current))
            return 0
        baseline = json.loads(args.baseline.read_bytes())
        validate(baseline)
        old = {r['id']: r for r in baseline['records']}
        new = {r['id']: r for r in current['records']}
        added, removed = sorted(new.keys() - old.keys()), sorted(old.keys() - new.keys())
        changed = sorted(k for k in new.keys() & old.keys() if new[k] != old[k])
        if args.mode == 'check':
            if canonical(current) != canonical(baseline):
                raise CatalogError('offline snapshot differs from pinned ST input')
        else:
            args.output.write_bytes(canonical({'added': added, 'removed': removed, 'changed': changed,
                                                'candidate': current}))
            if added or removed or changed:
                raise CatalogError(f'upstream drift: {len(added)} added, {len(removed)} removed, {len(changed)} changed')
        return 0
    except (CatalogError, OSError, UnicodeError, KeyError, TypeError, subprocess.CalledProcessError) as exc:
        print(f'STM32 catalog: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
