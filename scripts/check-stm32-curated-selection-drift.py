#!/usr/bin/env python3
"""Check current public board-use evidence for the reviewed F103 selection."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys

MAX_BYTES = 2_000_000

class DriftError(ValueError):
    pass

def bounded(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_BYTES:
        raise DriftError(f'unsafe or oversized input: {path.name}')
    return path.read_text(encoding='utf-8')

def check(arduino_readme, cube_example):
    arduino = bounded(arduino_readme)
    cube = bounded(cube_example)
    checks = {
        'STM32F103C8T6': 'STM32F103C8T6-Blue-Pill' in arduino,
        'STM32F103CBT6': 'STM32F103CB' in arduino,
        'STM32F103RBT6': 'STM32F103RBT6' in cube,
    }
    return {'$schema': 'urn:embedra:schema:stm32-curated-selection-drift:1',
            'checks': checks, 'status': 'PASS' if all(checks.values()) else 'REVIEW_REQUIRED'}

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--arduino-readme', type=Path, required=True)
    p.add_argument('--cube-example', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    try:
        result = check(a.arduino_readme, a.cube_example)
        a.output.write_text(json.dumps(result, sort_keys=True, separators=(',', ':')) + '\n')
        if result['status'] != 'PASS':
            raise DriftError('selected board evidence changed; review required')
        return 0
    except (DriftError, OSError, UnicodeError) as exc:
        print(f'STM32 selection drift: {exc}', file=sys.stderr)
        return 1

if __name__ == '__main__':
    raise SystemExit(main())
