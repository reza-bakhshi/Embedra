#!/usr/bin/env python3
"""Report ST GitHub device-family-pack repositories not yet classified.

ST moved the STM32C5 DFP to the BSD-3-Clause ``stm32c5xx-dfp`` repository,
which is the only currently known permissively licensed exact-part source. This
check reads a previously fetched GitHub repository listing (no network here) and
flags new STM32 ``*-dfp`` repositories so a maintainer can audit their license
and exact-part coverage before T032 relies on them.

Exit status is non-zero when an unclassified candidate appears, which a
scheduled workflow treats as a review trigger. It never fetches or writes
vendor source data itself.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys

SCHEMA = 'urn:embedra:schema:stm32-dfp-source-audit:1'
DEFAULT_KNOWN = ('stm32c5xx-dfp',)
CANDIDATE = re.compile(r'^stm32[a-z0-9]+-dfp$')
MAX_REPOS = 50_000


class DiscoveryError(ValueError):
    pass


def canonical(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=False,
                       separators=(',', ':')) + '\n').encode()


def load_repositories(path):
    if path.is_symlink() or not path.is_file():
        raise DiscoveryError('repository listing is missing or unsafe')
    try:
        payload = json.loads(path.read_bytes())
    except json.JSONDecodeError as exc:
        raise DiscoveryError(f'malformed repository listing: {exc}') from exc
    if isinstance(payload, dict):
        payload = payload.get('items')
    if not isinstance(payload, list) or len(payload) > MAX_REPOS:
        raise DiscoveryError('repository listing has an unexpected shape')
    repositories = []
    for entry in payload:
        if not isinstance(entry, dict):
            raise DiscoveryError('repository entry is not an object')
        name = entry.get('name')
        if not isinstance(name, str):
            raise DiscoveryError('repository entry lacks a name')
        repositories.append(entry)
    return repositories


def audit(repositories, known):
    found = {}
    for entry in repositories:
        name = entry['name']
        if not CANDIDATE.fullmatch(name.lower()):
            continue
        license_info = entry.get('license')
        spdx = license_info.get('spdx_id') if isinstance(license_info, dict) else None
        found[name] = {
            'name': name,
            'archived': bool(entry.get('archived', False)),
            'defaultBranch': entry.get('default_branch'),
            'license': spdx or 'NOASSERTION',
            'url': entry.get('html_url'),
        }
    known_set = {name.lower() for name in known}
    classified = sorted(name for name in found if name.lower() in known_set)
    candidates = sorted(name for name in found if name.lower() not in known_set)
    return {
        '$schema': SCHEMA,
        'known': classified,
        'candidates': [found[name] for name in candidates],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repos-json', type=Path, required=True)
    parser.add_argument('--known', action='append', default=None)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    try:
        known = tuple(args.known) if args.known else DEFAULT_KNOWN
        report = audit(load_repositories(args.repos_json), known)
        data = canonical(report)
        if args.output is not None:
            args.output.write_bytes(data)
        if report['candidates']:
            print('Unclassified STM32 DFP repositories: '
                  + ', '.join(row['name'] for row in report['candidates']),
                  file=sys.stderr)
            return 1
        print('ST STM32 DFP repository set is unchanged: '
              + ', '.join(report['known']))
        return 0
    except (DiscoveryError, OSError, KeyError, TypeError, ValueError) as exc:
        print(f'STM32 DFP discovery: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
