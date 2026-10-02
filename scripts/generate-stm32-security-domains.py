#!/usr/bin/env python3
"""Generate the digest-pinned STM32 security-domain snapshot (T044).

The snapshot records only TrustZone facts that the pinned sources actually
fix, per exact curated part:

* The secure-alias base addresses and their ``_BASE_NS`` counterparts come from
  the pinned Apache-2.0 ST CMSIS device headers already audited by T039
  (``.embedra/evidence/tasks/T039-memory-header-evidence.json``), which carries
  the repository, commit, path, and SHA-256 of every header file.
* The alias aperture size and its paired target region come from the pinned
  T039 ``memory-plans.json`` alias entry (the same reviewed alias the plan
  already exposes); the window is emitted only when the header base, the plan
  alias, and the plan region agree.
* The TrustZone ``SecureFault`` exception and the ``FLASH_SECWM``
  configuration-register evidence come from the pinned CMSIS interrupt index
  and the same headers.

No secure/non-secure partition boundary, non-secure-callable address, veneer
address, or instruction semantics is invented. The NSC boundary is
configuration-dependent (``SECWM``/option bytes) and is recorded explicitly as
``UNAVAILABLE`` with a reason. A part with no pinned secure alias stays
``UNAVAILABLE`` with a reason and no data.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import re
from pathlib import Path
import sys

SCHEMA = 'urn:embedra:schema:stm32-security-domains:1'
EXPECTED_CURATED_SHA256 = 'afc66a47cd79c2025d115049c8aebd2db671c1112d42531b1db50df8514858f9'
EXPECTED_SELECTION_SHA256 = '1d4b971f0264815492bf644552b8c83abf0393b627216a89640080b8ccf8b3b4'
EXPECTED_HEADER_EVIDENCE_SHA256 = \
    '491c148f623de7ac3e14f2c1e99ec919b3223afda470d57de3040405ed07a4a5'
EXPECTED_INTERRUPTS_SHA256 = \
    '2c312786d907f85babde522944141d0672094749e787ce87078c14bc07495f72'
EXPECTED_MEMORY_PLANS_SHA256 = \
    '00def2817ba0660644a4bc6cea3ffb756e11aff4d7236a466f82de838c280c66'

SECURE_BASE = re.compile(r'^[A-Z0-9_]+_BASE_S$')
NON_SECURE_BASE = re.compile(r'^[A-Z0-9_]+_BASE_NS$')
LITERAL_ADDRESS = re.compile(r'^\(?\s*(0x[0-9A-Fa-f]+)U?L?\s*\)?')
SECWM_SYMBOL = re.compile(r'^FLASH_SECWM.*_(PEND|END)$')

ALIAS_STATUS = 'ALIAS_VIEWS_PINNED'
UNAVAILABLE_STATUS = 'UNAVAILABLE'
NSC_REASON = 'NSC_REGION_CONFIGURATION_DEPENDENT'
NO_TRUSTZONE_REASON = 'NO_PINNED_TRUSTZONE_ALIAS_EVIDENCE'
NS_ONLY_REASON = 'NON_SECURE_SUFFIXED_ALIASES_ONLY'
NO_ALIAS_REASON = 'NO_SECURE_NS_ALIAS_DECLARATIONS'

SYSTEM_PREFIXES = ('SYSTEM', 'FLASH_SYSTEM', 'BOOTROM')


class SecurityDomainError(ValueError):
    pass


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'),
                       ensure_ascii=False) + '\n').encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def load_pinned(path, expected, label):
    data = Path(path).read_bytes()
    if sha(data) != expected:
        raise SecurityDomainError(f'{label} digest does not match the pin')
    return json.loads(data)


def literal(declaration):
    match = LITERAL_ADDRESS.match(declaration.strip())
    return int(match.group(1), 16) if match else None


def kind_for(prefix):
    if prefix in SYSTEM_PREFIXES:
        return 'SYSTEM'
    return 'FLASH' if prefix.startswith('FLASH') else 'RAM'


def header_sources(part, headers, sources):
    result = []
    for path in headers:
        source = sources.get(path)
        if source is None:
            raise SecurityDomainError(f'{part}: header {path} is not pinned')
        result.append({
            'repository': source['repository'],
            'commit': source['commit'],
            'path': source['path'],
            'sha256': source['sha256'],
            'license': source['license'],
        })
    result.sort(key=lambda item: item['path'])
    return result


def declarations_for(headers, sources):
    result = []
    for path in headers:
        source = sources.get(path)
        if source is None:
            raise SecurityDomainError(f'header {path} is not pinned')
        result.extend((source['path'], declaration)
                      for declaration in source['declarations'])
    return result


def windows_for(part, declarations, plan, sources):
    regions = {region['id']: region for region in plan['regions']}
    aliases = plan['aliases']
    secure_bases = {}
    non_secure_bases = {}
    for path, declaration in declarations:
        name = declaration['name']
        if SECURE_BASE.match(name) and literal(declaration['declaration']) is not None:
            secure_bases.setdefault(name, []).append((path, declaration))
        elif NON_SECURE_BASE.match(name) and literal(declaration['declaration']) is not None:
            non_secure_bases.setdefault(name, []).append((path, declaration))
    windows = []
    unresolved = []
    for name in sorted(secure_bases):
        entries = secure_bases[name]
        if len(entries) > 1:
            raise SecurityDomainError(f'{part}: duplicate secure alias symbol {name}')
        path, declaration = entries[0]
        start = literal(declaration['declaration'])
        prefix = name[:-len('_BASE_S')]
        counterpart = non_secure_bases.get(prefix + '_BASE_NS')
        if not counterpart:
            unresolved.append({'symbol': name, 'reason': 'NO_NS_COUNTERPART'})
            continue
        non_secure_base = literal(counterpart[0][1]['declaration'])
        region = next((candidate for candidate in plan['regions']
                       if candidate['start'] == non_secure_base), None)
        if region is None:
            unresolved.append({'symbol': name, 'reason': 'NO_T039_REGION_AT_NS_BASE'})
            continue
        candidates = [alias for alias in aliases
                      if alias['start'] == start and alias['target'] == region['id']]
        if not candidates:
            unresolved.append(
                {'symbol': name, 'reason': 'NO_T039_SECURE_VIEW_ALIAS_AT_S_BASE'})
            continue
        sizes = {alias['size'] for alias in candidates}
        if len(sizes) != 1:
            raise SecurityDomainError(f'{part}: aliases for {name} disagree on size')
        windows.append({
            'id': prefix + '_S',
            'kind': kind_for(prefix),
            'attribute': 'SECURE',
            'boundaryKind': 'ALIAS_APERTURE',
            'start': start,
            'size': sizes.pop(),
            'pairedRegionId': region['id'],
            'pairedAliasIds': sorted(alias['id'] for alias in candidates),
            'baseSymbol': name,
            'baseLine': declaration['line'],
            'baseDeclaration': declaration['declaration'],
            'headerPath': path,
            'partitionState': 'UNRESOLVED_CONFIGURATION_DEPENDENT',
        })
    windows.sort(key=lambda window: (window['start'], window['id']))
    unresolved.sort(key=lambda item: item['symbol'])
    return windows, unresolved


def nsc_evidence(declarations):
    return sorted({declaration['name'] for _, declaration in declarations
                   if SECWM_SYMBOL.match(declaration['name'])})


def secure_fault(part, headers, interrupts):
    for path in headers:
        for entry in interrupts['headers'].get(path, {}).get('interrupts', []):
            if entry['name'] == 'SecureFault_IRQn':
                return {'name': entry['name'], 'number': entry['number']}
    return None


def generate(header_evidence, memory_plans, curated, selection, interrupts):
    evidence = load_pinned(header_evidence, EXPECTED_HEADER_EVIDENCE_SHA256,
                           'STM32 header evidence')
    plans = load_pinned(memory_plans, EXPECTED_MEMORY_PLANS_SHA256, 'STM32 memory plans')
    catalog = load_pinned(curated, EXPECTED_CURATED_SHA256, 'STM32 curated catalog')
    curated_selection = load_pinned(selection, EXPECTED_SELECTION_SHA256,
                                    'STM32 selection')
    interrupt_index = load_pinned(interrupts, EXPECTED_INTERRUPTS_SHA256,
                                  'STM32 interrupt index')
    selected = [entry['exactPart'] for entry in curated_selection['parts']]
    if len(selected) != len(set(selected)):
        raise SecurityDomainError('selection contains duplicate exact parts')
    catalog_parts = [record['exactPart'] for record in catalog['records']]
    if sorted(catalog_parts) != sorted(selected):
        raise SecurityDomainError('curated catalog does not match the selection')
    plan_by_part = {record['exactPart']: record for record in plans['records']}
    evidence_by_part = {record['exactPart']: record for record in evidence['records']}
    if sorted(plan_by_part) != sorted(selected):
        raise SecurityDomainError('memory plans do not cover the selection')
    if sorted(evidence_by_part) != sorted(selected):
        raise SecurityDomainError('header evidence does not cover the selection')
    records = []
    alias_count = 0
    for part in sorted(selected):
        headers = sorted(set(evidence_by_part[part]['headers']))
        sources = header_sources(part, headers, evidence['sources'])
        declarations = declarations_for(headers, evidence['sources'])
        plan = plan_by_part[part]
        windows, unresolved = windows_for(part, declarations, plan, evidence['sources'])
        fault = secure_fault(part, headers, interrupt_index)
        if windows:
            alias_count += 1
            records.append({
                'exactPart': part,
                'status': ALIAS_STATUS,
                'reason': None,
                'sourceHeaders': sources,
                'windows': windows,
                'unresolvedAliasSymbols': unresolved,
                'nonSecureCallable': {
                    'status': UNAVAILABLE_STATUS,
                    'reason': NSC_REASON,
                    'configurationEvidence': nsc_evidence(declarations),
                },
                'veneerEvidence': {
                    'status': UNAVAILABLE_STATUS,
                    'reason': NSC_REASON,
                    'secureFaultException': fault,
                    'transitions': [],
                },
            })
            continue
        has_non_secure_suffix = any(
            NON_SECURE_BASE.match(declaration['name']) for _, declaration in declarations)
        reason = NS_ONLY_REASON if has_non_secure_suffix else NO_ALIAS_REASON
        records.append({
            'exactPart': part,
            'status': UNAVAILABLE_STATUS,
            'reason': reason,
            'sourceHeaders': sources,
            'windows': [],
            'unresolvedAliasSymbols': [],
            'nonSecureCallable': {
                'status': UNAVAILABLE_STATUS,
                'reason': NO_TRUSTZONE_REASON,
                'configurationEvidence': [],
            },
            'veneerEvidence': {
                'status': UNAVAILABLE_STATUS,
                'reason': NO_TRUSTZONE_REASON,
                'secureFaultException': None,
                'transitions': [],
            },
        })
    return {
        '$schema': SCHEMA,
        'curatedCatalogSha256': EXPECTED_CURATED_SHA256,
        'selectionSha256': EXPECTED_SELECTION_SHA256,
        'cmsisHeaderEvidenceSha256': EXPECTED_HEADER_EVIDENCE_SHA256,
        'cmsisInterruptIndexSha256': EXPECTED_INTERRUPTS_SHA256,
        'memoryPlansSha256': EXPECTED_MEMORY_PLANS_SHA256,
        'aliasViewParts': alias_count,
        'unavailableParts': len(records) - alias_count,
        'records': records,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['generate', 'check'])
    parser.add_argument('--header-evidence', type=Path, required=True)
    parser.add_argument('--memory-plans', type=Path, required=True)
    parser.add_argument('--curated', type=Path, required=True)
    parser.add_argument('--selection', type=Path, required=True)
    parser.add_argument('--interrupts', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        data = canonical(generate(args.header_evidence, args.memory_plans,
                                  args.curated, args.selection, args.interrupts))
        if args.mode == 'generate':
            args.output.write_bytes(data)
            args.output.with_suffix('.sha256').write_text(sha(data) + '\n')
        elif args.output.read_bytes() != data:
            raise SecurityDomainError(
                'security domains differ from the pinned sources')
        return 0
    except (SecurityDomainError, OSError, KeyError, TypeError, ValueError) as exc:
        print(f'STM32 security domains: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
