#!/usr/bin/env python3
"""Resolve exact STM32 SVD applicability for the curated 53-part selection.

The resolution is explicit and reviewable: an SVD device line is associated with
an exact curated part only by an exact device-name prefix or a named review
override. Family names, wildcard device names (for example ``STM32U5Gx``), and
neighbouring device lines never establish applicability. Unresolved parts stay
``UNAVAILABLE`` with a reason and no data is fabricated.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import sys

SCHEMA = 'urn:embedra:schema:stm32-svd-applicability:1'
SOURCE_IDENTITY = 'ST-authored SVD via modm-io/cmsis-svd-stm32'
SOURCE_URL = 'https://github.com/modm-io/cmsis-svd-stm32'
SOURCE_REVISION = 'e79021accd49bf19bd0b16065f5471fb073ff3ac'
SOURCE_LICENSE = 'Apache-2.0'
SOURCE_REDISTRIBUTION = 'DERIVED_FACTS_ALLOWED'
SELECTION_RULE = 'EXPLICIT_EXACT_DEVICE_LINE_REVIEW_NO_FAMILY_OR_WILDCARD'
EXPECTED_CURATED_SHA256 = 'afc66a47cd79c2025d115049c8aebd2db671c1112d42531b1db50df8514858f9'
EXPECTED_RULES_SHA256 = '16cb39d558e249f9c6a4020e39b77644d70af2d07b2df01becc732e4d6056ace'

# Device lines whose packs are generated and shipped with this task. Every other
# exact mapping stays explicit as EXACT_SVD_DEFERRED and applies no register data.
SHIPPED_PARTS = {
    'STM32C031C6T3', 'STM32F103C8T6', 'STM32F103CBT6', 'STM32F103RBT6',
    'STM32F401RET6', 'STM32H503RBT6', 'STM32H735IGK6', 'STM32WB55RGV6',
}

# Individual review decisions that an exact-name prefix cannot express.
REVIEWED_OVERRIDES = {
    'STM32WB15CCU6': {
        'deviceNames': ['STM32WB15_CM4'],
        'reason': 'DUAL_CORE_M4_SVD_AVAILABLE_M0P_DEVICE_LINE_ABSENT',
    },
    'STM32WB55RGV6': {
        'deviceNames': ['STM32WB55_CM4', 'STM32WB55_CM0P'],
        'reason': 'DUAL_CORE_PER_CORE_SVD_REVIEWED',
    },
}

# Exact parts whose device line is absent (or only present as a forbidden
# wildcard) in the pinned source; mapping a neighbouring line is not allowed.
UNAVAILABLE_REASONS = {
    'STM32F207ZGT6': 'NO_EXACT_SVD_DEVICE_LINE_IN_PINNED_SOURCE',
    'STM32H553ZGT6': 'NO_EXACT_SVD_DEVICE_LINE_IN_PINNED_SOURCE',
    'STM32U3C5ZIT6Q': 'NO_EXACT_SVD_DEVICE_LINE_IN_PINNED_SOURCE',
    'STM32U5G9NJH6Q': 'ONLY_WILDCARD_DEVICE_NAME_IN_PINNED_SOURCE',
    'STM32U5G9ZJT6Q': 'ONLY_WILDCARD_DEVICE_NAME_IN_PINNED_SOURCE',
    'STM32WBA25CEU7': 'NO_EXACT_SVD_DEVICE_LINE_IN_PINNED_SOURCE',
    'STM32WBA65RIV7': 'NO_EXACT_SVD_DEVICE_LINE_IN_PINNED_SOURCE',
    'STM32WL3RKBV6': 'NO_EXACT_SVD_DEVICE_LINE_IN_PINNED_SOURCE',
}


class ApplicabilityError(ValueError):
    pass


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'),
                       ensure_ascii=False) + '\n').encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def exact_prefix(part, device_name):
    """True only for a non-wildcard device-name prefix of the exact part."""
    if 'X' in device_name.upper():
        return False
    return part.upper().startswith(device_name.upper())


def generate(curated_path, rules_path):
    curated_bytes = Path(curated_path).read_bytes()
    rules_bytes = Path(rules_path).read_bytes()
    curved_sha = sha(curated_bytes)
    rules_sha = sha(rules_bytes)
    if curved_sha != EXPECTED_CURATED_SHA256:
        raise ApplicabilityError('curated catalog digest does not match the pin')
    if rules_sha != EXPECTED_RULES_SHA256:
        raise ApplicabilityError('SVD rule index digest does not match the pin')
    curated = json.loads(curated_bytes)
    rules = json.loads(rules_bytes)
    files = rules['files']
    by_name = {}
    for path, facts in files.items():
        by_name.setdefault(facts['deviceName'], []).append((path, facts))
    records = curated['records']
    if len(records) != 53:
        raise ApplicabilityError('curated catalog must contain 53 exact parts')
    parts = []
    for record in sorted(records, key=lambda item: item['exactPart']):
        part = record['exactPart']
        reason = None
        if part in UNAVAILABLE_REASONS:
            status = 'UNAVAILABLE'
            names = []
            reason = UNAVAILABLE_REASONS[part]
        elif part in REVIEWED_OVERRIDES:
            override = REVIEWED_OVERRIDES[part]
            names = list(override['deviceNames'])
            reason = override['reason']
            status = 'EXACT_SVD_SHIPPED' if part in SHIPPED_PARTS \
                else 'EXACT_SVD_DEFERRED'
        else:
            names = sorted(name for name in by_name if exact_prefix(part, name))
            if not names:
                status = 'UNAVAILABLE'
                reason = 'NO_EXACT_SVD_DEVICE_LINE_IN_PINNED_SOURCE'
            elif len(names) > 1:
                status = 'AMBIGUOUS'
                reason = 'MULTIPLE_EXACT_DEVICE_LINES'
            else:
                status = 'EXACT_SVD_SHIPPED' if part in SHIPPED_PARTS \
                    else 'EXACT_SVD_DEFERRED'
        svd_files = []
        for name in names:
            entries = by_name.get(name, [])
            if len(entries) != 1:
                raise ApplicabilityError(
                    'device line is not uniquely pinned: ' + name)
            path, facts = entries[0]
            svd_files.append({'deviceName': name, 'path': path,
                              'sha256': facts['sha256'], 'cpu': facts['cpu']})
        parts.append({
            'exactPart': part,
            'family': record['family'],
            'status': status,
            'svdFiles': svd_files,
            'reason': reason,
        })
    shipped = sorted({entry['deviceName'] for part in parts
                      if part['status'] == 'EXACT_SVD_SHIPPED'
                      for entry in part['svdFiles']})
    return {
        '$schema': SCHEMA,
        'curatedCatalogSha256': curved_sha,
        'svdRuleIndexSha256': rules_sha,
        'source': {
            'identity': SOURCE_IDENTITY,
            'url': SOURCE_URL,
            'revision': SOURCE_REVISION,
            'license': SOURCE_LICENSE,
            'redistribution': SOURCE_REDISTRIBUTION,
        },
        'selectionRule': SELECTION_RULE,
        'shippedDeviceLines': shipped,
        'parts': parts,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['generate', 'check'])
    parser.add_argument('--curated', type=Path, required=True)
    parser.add_argument('--rules', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        data = canonical(generate(args.curated, args.rules))
        if args.mode == 'generate':
            args.output.write_bytes(data)
        elif args.output.read_bytes() != data:
            raise ApplicabilityError('applicability differs from the pinned sources')
        return 0
    except (ApplicabilityError, OSError, KeyError, TypeError) as exc:
        print(f'STM32 SVD applicability: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
