#!/usr/bin/env python3
"""Report missing mandatory facts before STM32 exact-part memory planning.

This is an audit of committed, digest-pinned facts. It never fills a missing
bank, flash size, or processor from a family-level guess.
"""

import argparse
import hashlib
import json
from pathlib import Path


CATALOG_SHA256 = 'afc66a47cd79c2025d115049c8aebd2db671c1112d42531b1db50df8514858f9'
CATALOG_SCHEMA = 'urn:embedra:schema:stm32-curated-catalog:1'
ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / 'catalogs/stm32/2026-09-29/curated-catalog.json'


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def gaps(record):
    missing = []
    if record.get('flashKiB') is None:
        missing.append('FLASH_SIZE_UNPAIRED')
    if not record.get('memoryBanks') or record.get('memoryBanksStatus') == 'UNKNOWN':
        missing.append('MEMORY_BANKS_UNKNOWN')
    if not record.get('processors'):
        missing.append('PROCESSORS_UNKNOWN')
    return missing


def audit_bytes(data):
    if sha256(data) != CATALOG_SHA256:
        raise ValueError('STM32 curated catalog digest mismatch')
    catalog = json.loads(data)
    if catalog.get('$schema') != CATALOG_SCHEMA:
        raise ValueError('STM32 curated catalog schema mismatch')
    records = catalog.get('records')
    if not isinstance(records, list) or len(records) != 53:
        raise ValueError('STM32 curated catalog must contain 53 records')
    findings = {record['exactPart']: gaps(record) for record in records}
    return {
        'catalogSha256': CATALOG_SHA256,
        'recordCount': len(records),
        'readyCount': sum(not missing for missing in findings.values()),
        'missingMemoryBanks': sum('MEMORY_BANKS_UNKNOWN' in missing
                                  for missing in findings.values()),
        'unresolvedFlash': sum('FLASH_SIZE_UNPAIRED' in missing
                               for missing in findings.values()),
        'missingProcessors': sum('PROCESSORS_UNKNOWN' in missing
                                 for missing in findings.values()),
        'incompleteParts': {part: findings[part] for part in sorted(findings)
                            if findings[part]},
    }


def audit_catalog(path=CATALOG):
    return audit_bytes(Path(path).read_bytes())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--require-complete', action='store_true',
                        help='Exit nonzero if any selected part lacks mandatory facts')
    args = parser.parse_args()
    result = audit_catalog()
    print(json.dumps(result, sort_keys=True, separators=(',', ':')))
    return int(args.require_complete and result['readyCount'] != result['recordCount'])


if __name__ == '__main__':
    raise SystemExit(main())
