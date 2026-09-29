#!/usr/bin/env python3
"""Reconcile exact ST board CPNs with licensed pin and CMSIS source facts."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
BOARD = ROOT / 'catalogs/stm32/sources/board-index.json'
PIN = ROOT / 'catalogs/stm32/2026-09-28/source-catalog.json'
CMSIS = ROOT / 'catalogs/stm32/2026-09-28/cmsis-interrupts.json'
OUTPUT = ROOT / 'catalogs/stm32/sources/board-part-candidates.json'
MAX_BYTES = 4_000_000
EXACT = re.compile(r'STM32[A-Z0-9]+\Z')

class CandidateError(ValueError):
    pass

def sha(data):
    return hashlib.sha256(data).hexdigest()

def canonical(obj):
    return (json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False) + '\n').encode()

def read(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_BYTES:
        raise CandidateError(f'unsafe/oversized input: {path.name}')
    data = path.read_bytes()
    try:
        return json.loads(data), sha(data)
    except (ValueError, UnicodeError) as exc:
        raise CandidateError(f'invalid JSON: {path.name}') from exc

def generate(board_path=BOARD, pin_path=PIN, cmsis_path=CMSIS):
    boards, board_sha = read(board_path)
    pins, pin_sha = read(pin_path)
    cmsis, cmsis_sha = read(cmsis_path)
    if boards.get('$schema') != 'urn:embedra:schema:stm32-board-index:1' or boards['source']['license'] != 'BSD-3-Clause':
        raise CandidateError('board source/license mismatch')
    if pins.get('$schema') != 'urn:embedra:schema:stm32-source-catalog:1' or pins['sources'][0]['license'] != 'BSD-3-Clause':
        raise CandidateError('pin source/license mismatch')
    if cmsis.get('sourceCatalogSha256') != pin_sha or any(x['license'] != 'Apache-2.0' for x in cmsis['repositories']):
        raise CandidateError('CMSIS source/license mismatch')
    refs = {x['id']: x for x in pins['records']}
    maps = {x['reference']: x for x in cmsis['mappings']}
    grouped = {}
    for row in boards['records']:
        part = row['exactPart']
        if part is None:
            continue
        if row['cpnStatus'] != 'EXACT' or not EXACT.fullmatch(part):
            raise CandidateError(f'nonexact board CPN: {part}')
        grouped.setdefault(part, []).append(row)
    if not grouped or len(grouped) > 1000:
        raise CandidateError('candidate count outside bounds')
    result = []
    for part in sorted(grouped):
        rows = grouped[part]
        ref_names = {x['reference'] for x in rows}
        packages = {x['package'] for x in rows}
        families = {x['family'] for x in rows}
        if len(ref_names) != 1 or len(packages) != 1 or len(families) != 1:
            raise CandidateError(f'conflicting board identity: {part}')
        ref_name = next(iter(ref_names))
        ref = refs.get(ref_name)
        mapping = maps.get(ref_name)
        if not ref or not mapping or ref['package'] != next(iter(packages)):
            raise CandidateError(f'unmatched source reference: {part}')
        headers = mapping['headers']
        irq_status = mapping['status']
        irq = []
        header_sha = None
        if irq_status == 'MAPPED_SINGLE' and len(headers) == 1:
            header = cmsis['headers'].get(headers[0])
            if not header or header['conditional']:
                raise CandidateError(f'unsafe IRQ inheritance: {part}')
            irq = header['interrupts']
            header_sha = header['sha256']
        board_family = next(iter(families))
        result.append({'exactPart': part, 'family': ref['family'],
                       'boardFamily': board_family,
                       'familyReconciliation': 'MATCHED' if board_family == ref['family'] else 'ALIAS_REVIEW',
                       'referencePattern': ref_name, 'package': ref['package'],
                       'flashKiBValues': ref['flashKiBValues'],
                       'flashPairingStatus': 'UNPAIRED_ALTERNATIVES' if len(ref['flashKiBValues']) != 1 else 'SINGLE_VALUE',
                       'ramKiBValues': ref['ramKiBValues'],
                       'ramPairingStatus': 'UNPAIRED_ALTERNATIVES' if len(ref['ramKiBValues']) != 1 else 'SINGLE_VALUE',
                       'processors': ref['processors'],
                       'securityEvidence': ref['securityEvidence'],
                       'securityStatus': 'UNKNOWN', 'lifecycle': 'UNKNOWN',
                       'deviceIds': [], 'deviceIdStatus': 'UNKNOWN',
                       'interruptStatus': irq_status, 'interruptHeaders': headers,
                       'interruptHeaderSha256': header_sha, 'interrupts': irq,
                       'svdStatus': 'EXACT_APPLICABILITY_UNVERIFIED',
                       'marketStatus': 'NOT_REVIEWED',
                       'boardEvidence': [{'board': x['board'], 'category': x['category'],
                                          'sourcePath': x['sourcePath'], 'sourceSha256': x['sourceSha256']}
                                         for x in sorted(rows, key=lambda r: r['sourcePath'])],
                       'sourceReferenceSha256': ref['sourceSha256']})
    return {'$schema': 'urn:embedra:schema:stm32-board-part-candidates:1',
            'sourceDigests': {'boardIndex': board_sha, 'pinCatalog': pin_sha, 'cmsisIndex': cmsis_sha},
            'licenses': ['BSD-3-Clause', 'Apache-2.0'], 'records': result}

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('mode', choices=('generate', 'check'))
    p.add_argument('--board', type=Path, default=BOARD)
    p.add_argument('--pin', type=Path, default=PIN)
    p.add_argument('--cmsis', type=Path, default=CMSIS)
    p.add_argument('--output', type=Path, default=OUTPUT)
    a = p.parse_args()
    try:
        data = canonical(generate(a.board, a.pin, a.cmsis))
        if a.mode == 'generate':
            a.output.write_bytes(data)
            a.output.with_suffix('.sha256').write_text(sha(data) + '\n')
        elif a.output.read_bytes() != data or a.output.with_suffix('.sha256').read_text().strip() != sha(data):
            raise CandidateError('candidate snapshot differs')
        return 0
    except (CandidateError, OSError, KeyError, TypeError, IndexError) as exc:
        print(f'STM32 board candidates: {exc}', file=sys.stderr)
        return 1

if __name__ == '__main__':
    raise SystemExit(main())
