#!/usr/bin/env python3
"""Validate an explicit STM32 exact-part selection against pinned open ST/CMSIS facts."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'catalogs/stm32/2026-09-28/source-catalog.json'
CMSIS = ROOT / 'catalogs/stm32/2026-09-28/cmsis-interrupts.json'
SELECTION = ROOT / 'catalogs/stm32/2026-09-29/selection.json'
OUTPUT = ROOT / 'catalogs/stm32/2026-09-29/curated-catalog.json'
MAX_BYTES = 4_000_000
MAX_PARTS = 128
EXACT = re.compile(r'STM32[A-Z0-9]{8,24}\Z')
# Curated code-to-memory pairing is part of the review boundary, not inferred
# by expanding the ST reference wildcard/range.
F103_FLASH_CODE = {'8': 64, 'B': 128}
EXPECTED_PARTS = ('STM32F103C8T6', 'STM32F103CBT6', 'STM32F103RBT6')

class CuratedError(ValueError):
    pass


def sha(data):
    return hashlib.sha256(data).hexdigest()


def canonical(obj):
    return (json.dumps(obj, sort_keys=True, ensure_ascii=False,
                       separators=(',', ':')) + '\n').encode()


def read_json(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_BYTES:
        raise CuratedError(f'unsafe or oversized input: {path.name}')
    data = path.read_bytes()
    try:
        return json.loads(data), sha(data)
    except (ValueError, UnicodeError) as exc:
        raise CuratedError(f'invalid JSON: {path.name}') from exc


def generate(selection=SELECTION, source=SOURCE, cmsis=CMSIS):
    chosen, chosen_sha = read_json(selection)
    refs, refs_sha = read_json(source)
    irqs, irqs_sha = read_json(cmsis)
    if chosen.get('$schema') != 'urn:embedra:schema:stm32-curated-selection:1':
        raise CuratedError('selection schema mismatch')
    items = chosen.get('parts')
    if not isinstance(items, list) or not 1 <= len(items) <= MAX_PARTS:
        raise CuratedError('selection count outside bounds')
    if refs.get('$schema') != 'urn:embedra:schema:stm32-source-catalog:1' or irqs.get('sourceCatalogSha256') != refs_sha:
        raise CuratedError('source/CMSIS provenance mismatch')
    if any(x.get('license') != 'BSD-3-Clause' for x in refs['sources']):
        raise CuratedError('source license mismatch')
    if any(x.get('license') != 'Apache-2.0' for x in irqs['repositories']):
        raise CuratedError('CMSIS license mismatch')
    refs_by_id = {r['id']: r for r in refs['records']}
    maps_by_id = {m['reference']: m for m in irqs['mappings']}
    names = [x.get('exactPart') for x in items]
    if names != sorted(set(names)):
        raise CuratedError('parts must be sorted and unique')
    if tuple(names) != EXPECTED_PARTS:
        raise CuratedError('selection differs from reviewed acceptance set')
    records = []
    for item in items:
        name = item['exactPart']
        if not EXACT.fullmatch(name) or not name.startswith('STM32F103'):
            raise CuratedError(f'invalid or out-of-scope exact part: {name}')
        memory_code = name[10]
        if memory_code not in F103_FLASH_CODE or F103_FLASH_CODE[memory_code] != item['flashKiB']:
            raise CuratedError(f'flash code mismatch: {name}')
        if name[11] != 'T' or name[12] != '6' or len(name) != 13:
            raise CuratedError(f'package/temperature suffix mismatch: {name}')
        expected_ref = ('STM32F103C(8-B)Tx' if name[9] == 'C' else
                        'STM32F103R(8-B)Tx' if name[9] == 'R' else None)
        if item['reference'] != expected_ref:
            raise CuratedError(f'exact/reference mapping mismatch: {name}')
        ref = refs_by_id.get(expected_ref)
        mapping = maps_by_id.get(expected_ref)
        if not ref or not mapping or mapping['status'] != 'MAPPED_SINGLE' or len(mapping['headers']) != 1:
            raise CuratedError(f'missing unambiguous source/header: {name}')
        if ref['package'] != item['package'] or item['flashKiB'] not in ref['flashKiBValues'] or item['ramKiB'] not in ref['ramKiBValues']:
            raise CuratedError(f'package/memory not attested: {name}')
        if not item['orderabilityUrl'].startswith('https://www.st.com/en/microcontrollers-microprocessors/') or not item['commonUseUrl'].startswith('https://'):
            raise CuratedError(f'missing selection evidence: {name}')
        header_path = mapping['headers'][0]
        header = irqs['headers'].get(header_path)
        if not header or header['conditional'] or not header['interrupts']:
            raise CuratedError(f'conditional or absent IRQ header: {name}')
        records.append({
            'exactPart': name, 'identityKind': 'EXACT_ORDERABLE_PART',
            'family': 'STM32F103', 'referencePattern': expected_ref,
            'package': item['package'], 'flashKiB': item['flashKiB'],
            'ramKiB': item['ramKiB'], 'processors': ref['processors'],
            'interrupts': header['interrupts'], 'interruptHeader': header_path,
            'securityEvidence': ref['securityEvidence'],
            'securityStatus': 'UNKNOWN', 'lifecycle': 'UNKNOWN',
            'deviceIds': [], 'deviceIdStatus': 'UNKNOWN',
            'svdTransformation': {'status': 'UNMAPPED', 'rule': 'REQUIRE_EXACT_CMSIS_DEVICE_MATCH'},
            'supportState': 'PLANNED',
            'sourceReferenceSha256': ref['sourceSha256'],
            'sourceHeaderSha256': header['sha256'],
            'orderabilityUrl': item['orderabilityUrl'],
            'commonUseUrl': item['commonUseUrl'],
        })
    return {'$schema': 'urn:embedra:schema:stm32-curated-catalog:1',
            'selectionSha256': chosen_sha,
            'sourceCatalogSha256': refs_sha, 'cmsisIndexSha256': irqs_sha,
            'sourceLicenses': ['BSD-3-Clause', 'Apache-2.0'],
            'records': records}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('mode', choices=('generate', 'check'))
    p.add_argument('--selection', type=Path, default=SELECTION)
    p.add_argument('--source', type=Path, default=SOURCE)
    p.add_argument('--cmsis', type=Path, default=CMSIS)
    p.add_argument('--output', type=Path, default=OUTPUT)
    a = p.parse_args()
    try:
        data = canonical(generate(a.selection, a.source, a.cmsis))
        if a.mode == 'generate':
            a.output.write_bytes(data)
            a.output.with_suffix('.sha256').write_text(sha(data) + '\n')
        elif a.output.read_bytes() != data or a.output.with_suffix('.sha256').read_text().strip() != sha(data):
            raise CuratedError('curated offline snapshot differs')
        return 0
    except (CuratedError, OSError, KeyError, TypeError, IndexError) as exc:
        print(f'STM32 curated catalog: {exc}', file=sys.stderr)
        return 1

if __name__ == '__main__':
    raise SystemExit(main())
