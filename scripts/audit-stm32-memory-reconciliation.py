#!/usr/bin/env python3
"""Check T039 partial evidence consistency without accepting runtime bank maps."""

import argparse
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / '.embedra/evidence/tasks'


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def audit(review, catalog, candidates, headers):
    if review.get('schema') != 'embedra.stm32.memory-reconciliation.v1':
        raise ValueError('reconciliation schema mismatch')
    if review.get('status') != 'PARTIAL_SOURCE_REVIEW_NO_RUNTIME_MAPS':
        raise ValueError('partial evidence cannot promote runtime maps')
    selected = {r['exactPart'] for r in catalog['records']}
    rows = review['records']
    if len(rows) != len(selected) or {r['exactPart'] for r in rows} != selected:
        raise ValueError('reconciliation must cover every exact selected part once')
    candidate_rows = {r['exactPart']: r for r in candidates['records']}
    header_rows = {r['exactPart']: r for r in headers['records']}
    partial = 0
    regions = 0
    for row in rows:
        part = row['exactPart']
        if row['status'] != 'INCOMPLETE_NOT_RUNTIME_MAP' or not row['remaining']:
            raise ValueError('partial record must retain its mandatory evidence gaps')
        if row['headers'] != header_rows[part]['headers']:
            raise ValueError('review references a different part/header scope')
        pattern = row['nameReview']['selectedDevicePattern']
        if pattern is not None and pattern not in {
                c['devicePattern'] for c in candidate_rows[part]['candidates']}:
            raise ValueError('review selected an absent device pattern')
        symbols = {d['name'] for name in row['headers']
                   for d in headers['sources'][name]['declarations']}
        known = row['knownRegions']
        identities = {r['id']: r for r in known}
        if len(identities) != len(known):
            raise ValueError('duplicate reviewed region')
        for region in known:
            start, size = region['start'], region['size']
            if (type(start) is not int or type(size) is not int
                    or start < 0 or size <= 0 or start + size > 0x100000000):
                raise ValueError('invalid reviewed memory extent')
            if not set(region['headerSymbols']) <= symbols:
                raise ValueError('reviewed region references absent header symbols')
            if 'aliasOf' in region:
                target = identities.get(region['aliasOf'])
                if target is None or 'aliasOf' in target or target['size'] != size:
                    raise ValueError('alias must reference one equal-size physical region')
                if region['status'] != 'RELATIONSHIP_REQUIRES_MANUAL_BYTE_PIN':
                    raise ValueError('unconfirmed alias relationship cannot be promoted')
        physical = [r for r in known if 'aliasOf' not in r]
        for i, first in enumerate(physical):
            for second in physical[i + 1:]:
                if first['start'] < second['start'] + second['size'] and (
                        second['start'] < first['start'] + first['size']):
                    raise ValueError('reviewed physical regions overlap')
        ram_review = row['ramCapacityReview']
        if 'physicalKiB' in ram_review:
            total = sum(r['size'] for r in physical if r['kind'] == 'RAM')
            if total != ram_review['physicalKiB'] * 1024:
                raise ValueError('physical capacity double-counts aliases or omits banks')
        partial += bool(known)
        regions += len(known)
    return {'selectedParts': len(rows), 'partsWithPartialRegionFacts': partial,
            'reviewedRegionFacts': regions, 'completeRuntimeMaps': 0}


def audit_files():
    review = json.loads((EVIDENCE / 'T039-memory-reconciliation.json').read_bytes())
    inputs = [('catalogSha256', ROOT / 'catalogs/stm32/2026-09-29/curated-catalog.json'),
              ('candidateSha256', EVIDENCE / 'T039-memory-candidates.json'),
              ('headerEvidenceSha256', EVIDENCE / 'T039-memory-header-evidence.json')]
    parsed = []
    for key, path in inputs:
        data = path.read_bytes()
        if sha256(data) != review[key]:
            raise ValueError(f'reconciliation source digest mismatch: {key}')
        parsed.append(json.loads(data))
    f103 = (EVIDENCE / 'T039-f103-source-audit.json').read_bytes()
    if sha256(f103) != review['f103AuditSha256']:
        raise ValueError('reconciliation F103 source digest mismatch')
    dfp = (EVIDENCE / 'T039-dfp-source-audit.json').read_bytes()
    if sha256(dfp) != parsed[1]['sourceAuditSha256']:
        raise ValueError('candidate DFP source audit digest mismatch')
    return audit(review, *parsed)


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    print(json.dumps(audit_files(), sort_keys=True))


if __name__ == '__main__':
    main()
