#!/usr/bin/env python3
"""Compare a fresh read-only ST eStore audit with the reviewed exact-part set."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys

MAX_BYTES = 250_000

def read(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_BYTES:
        raise ValueError(f'unsafe or oversized input: {path}')
    return json.loads(path.read_text())

def compare(selection, current):
    if selection.get('$schema') != 'urn:embedra:schema:stm32-curated-selection:2':
        raise ValueError('selection schema mismatch')
    if current.get('$schema') != 'urn:embedra:schema:stm32-estore-audit:1':
        raise ValueError('audit schema mismatch')
    chosen = {x['exactPart']: x for x in selection['parts'] if x['selectionReason'] == 'CURRENT_ST_NUCLEO_OR_DISCOVERY_EXACT_CPN'}
    rows = {x['exactPart']: x for x in current['rows']}
    if len(rows) != len(current['rows']) or len(chosen) > 160:
        raise ValueError('duplicate/oversized current audit')
    changes = []
    for part, prior in sorted(chosen.items()):
        row = rows.get(part)
        if not row or row.get('result') != 'PARSED':
            changes.append({'part': part, 'reason': 'CURRENT_PAGE_UNVERIFIED'})
        elif row.get('marketingStatus') != prior['marketingStatus'] or row.get('stockStatus') != prior['stockStatusOnSelectionDate']:
            changes.append({'part': part, 'reason': 'STATUS_CHANGED',
                            'marketingStatus': row.get('marketingStatus'),
                            'stockStatus': row.get('stockStatus')})
    return {'$schema': 'urn:embedra:schema:stm32-market-drift:1',
            'checkedDate': current['checkedDate'], 'reviewedParts': len(chosen),
            'changes': changes, 'status': 'REVIEW_REQUIRED' if changes else 'PASS'}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--selection', type=Path, required=True)
    parser.add_argument('--current', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        result = compare(read(args.selection), read(args.current))
        args.output.write_text(json.dumps(result, sort_keys=True, separators=(',', ':')) + '\n')
        return 0 if result['status'] == 'PASS' else 1
    except (ValueError, OSError, KeyError, TypeError) as exc:
        print(f'STM32 market drift: {exc}', file=sys.stderr)
        return 1

if __name__ == '__main__':
    raise SystemExit(main())
