#!/usr/bin/env python3
"""Index ST-made sample boards from the pinned BSD-3-Clause open pin source."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

PIN_REVISION = '7d1f1514ed5583ec5007ad91236b4e1d377295b1'
MAX_FILES = 1000
MAX_BYTES = 1_000_000
MAX_TOTAL_BYTES = 50_000_000
EXACT_PART = re.compile(r'STM32[A-Z0-9]+\Z')
KEYS = {'Mcu.CPN', 'Mcu.Name', 'Mcu.Family', 'Mcu.Package', 'board'}

class BoardError(ValueError):
    pass

def sha(data):
    return hashlib.sha256(data).hexdigest()

def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False) + '\n').encode()

def parse(data, path):
    try:
        text = data.decode('utf-8-sig')
    except UnicodeError as exc:
        raise BoardError(f'non-UTF8 board file: {path.name}') from exc
    values = {}
    for line in text.splitlines():
        if not line or line.startswith('#'):
            continue
        if '=' not in line:
            raise BoardError(f'malformed board line: {path.name}')
        key, value = line.split('=', 1)
        if key in KEYS:
            if key in values or not value or len(value) > 128:
                raise BoardError(f'duplicate/invalid {key}: {path.name}')
            values[key] = value
    required = ('Mcu.Name', 'Mcu.Family', 'Mcu.Package')
    if any(k not in values for k in required):
        raise BoardError(f'missing board identity: {path.name}')
    if not values['Mcu.Name'].startswith('STM32') or not values['Mcu.Family'].startswith('STM32'):
        raise BoardError(f'not an STM32 board: {path.name}')
    category = next((name for name in ('Nucleo', 'Discovery', 'Evaluation')
                     if '_' + name + '_' in path.name), 'Other')
    board = values.get('board')
    if board is None:
        match = re.search(r'_(?:Nucleo|Discovery|Evaluation_Board)_(.+?)_STM32', path.name)
        if not match:
            raise BoardError(f'missing board identity: {path.name}')
        board = match.group(1)
    cpn = values.get('Mcu.CPN')
    return {'board': board, 'category': category,
            'reference': values['Mcu.Name'], 'family': values['Mcu.Family'],
            'package': values['Mcu.Package'],
            'exactPart': cpn if cpn and EXACT_PART.fullmatch(cpn) else None,
            'cpnStatus': 'EXACT' if cpn and EXACT_PART.fullmatch(cpn) else
                         'REFERENCE_ONLY' if cpn is None else 'NONEXACT_CPN',
            'sourcePath': 'boards/' + path.name, 'sourceSha256': sha(data)}

def generate(repo, cancelled=lambda: False, require_pin=True):
    if repo.is_symlink() or not repo.is_dir():
        raise BoardError('unsafe/absent source repository')
    revision = subprocess.check_output(['git', '-C', str(repo), 'rev-parse', 'HEAD'], text=True).strip()
    if require_pin and revision != PIN_REVISION:
        raise BoardError('source revision mismatch')
    license_path = repo / 'LICENSE'
    if license_path.is_symlink() or not license_path.is_file():
        raise BoardError('missing source license')
    license_data = license_path.read_bytes()
    if b'Redistribution and use in source and binary forms' not in license_data:
        raise BoardError('source license is not redistributable BSD')
    board_dir = repo / 'boards'
    if board_dir.is_symlink() or not board_dir.is_dir():
        raise BoardError('unsafe/absent board directory')
    paths = sorted(board_dir.glob('*.ioc'), key=lambda p: p.name)
    if not paths or len(paths) > MAX_FILES:
        raise BoardError('board count outside bounds')
    rows = []
    total = 0
    for path in paths:
        if cancelled():
            raise BoardError('generation cancelled')
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_BYTES:
            raise BoardError(f'unsafe/oversized board: {path.name}')
        data = path.read_bytes()
        total += len(data)
        if total > MAX_TOTAL_BYTES:
            raise BoardError('source byte limit exceeded')
        rows.append(parse(data, path))
    names = [x['sourcePath'] for x in rows]
    if names != sorted(set(names)):
        raise BoardError('unsorted/duplicate source paths')
    return {'$schema': 'urn:embedra:schema:stm32-board-index:1',
            'source': {'identity': 'STMicroelectronics/STM32_open_pin_data',
                       'revision': revision, 'license': 'BSD-3-Clause',
                       'licenseSha256': sha(license_data),
                       'inputFiles': len(rows), 'inputBytes': total},
            'records': rows}

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('mode', choices=('generate', 'check', 'drift'))
    p.add_argument('--repo', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--baseline', type=Path)
    a = p.parse_args()
    try:
        data = canonical(generate(a.repo, require_pin=(a.mode != 'drift')))
        if a.mode == 'generate':
            a.output.write_bytes(data)
            a.output.with_suffix('.sha256').write_text(sha(data) + '\n')
        elif a.mode == 'check':
            if a.output.read_bytes() != data or a.output.with_suffix('.sha256').read_text().strip() != sha(data):
                raise BoardError('board index differs from pinned source')
        else:
            if a.baseline is None:
                raise BoardError('drift baseline required')
            a.output.write_bytes(data)
            if a.baseline.read_bytes() != data:
                raise BoardError('upstream board index changed; review candidate')
        return 0
    except (BoardError, OSError, subprocess.CalledProcessError) as exc:
        print(f'STM32 board index: {exc}', file=sys.stderr)
        return 1

if __name__ == '__main__':
    raise SystemExit(main())
