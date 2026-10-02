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
PLANS = ROOT / 'catalogs/stm32/2026-09-29/memory-plans.json'
PLANS_SHA256 = '00def2817ba0660644a4bc6cea3ffb756e11aff4d7236a466f82de838c280c66'
REVIEWED_PROFILES = {
    'F103_MEDIUM_DENSITY_SINGLE_CORE',
    'G4_CATEGORY2_SINGLE_CORE',
    'G4_CATEGORY3_SINGLE_CORE',
    'G4_CATEGORY4_SINGLE_CORE',
    'F2_SINGLE_CORE',
    'F4_F401_SINGLE_CORE',
    'F7_SINGLE_CORE',
    'L4_L412_SINGLE_CORE',
    'L4P5_PLUS_SINGLE_CORE',
    'L4R5_PLUS_SINGLE_CORE',
    'L5_SINGLE_CORE',
    'H5_SINGLE_CORE',
    'G0_SINGLE_CORE',
    'C0_SINGLE_CORE',
    'H7_SINGLE_CORE',
    'U0_SINGLE_CORE',
    'U5_SINGLE_CORE',
    'WBA_SINGLE_CORE',
    'H7RS_SINGLE_CORE',
    'WB0_SINGLE_CORE',
    'WL3_SINGLE_CORE',
    'U3_SINGLE_CORE',
    'N6_SINGLE_CORE',
    'WB_DUAL_CORE',
}
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


def plan_gaps(record):
    """Check mandatory map structure independently of its claimed validation status."""
    missing = []
    if record.get('status') != 'VALIDATED_MAP':
        return ['MEMORY_BANKS_UNKNOWN', *record.get('missingProperties', [])]
    regions = record.get('regions', [])
    by_id = {region.get('id'): region for region in regions}
    option_availability = record.get('optionAvailability', 'MEMORY_MAPPED')
    system_availability = record.get('systemAvailability', 'PRESENT')
    flash_availability = record.get('flashAvailability', 'PRESENT')
    for label, value, allowed in (
            ('flash', flash_availability, ('PRESENT', 'UNAVAILABLE')),
            ('system', system_availability, ('PRESENT', 'UNAVAILABLE')),
            ('option', option_availability, ('MEMORY_MAPPED', 'NOT_MEMORY_MAPPED'))):
        if value not in allowed:
            missing.append('INVALID_' + label.upper() + '_AVAILABILITY')
    option_mapped = option_availability == 'MEMORY_MAPPED'
    system_present = system_availability == 'PRESENT'
    flash_present = flash_availability == 'PRESENT'
    required_ids = set()
    if flash_present:
        required_ids.add('FLASH')
    if option_mapped:
        required_ids.add('OPTION')
    if system_present:
        required_ids.add('SYSTEM')
    if len(by_id) != len(regions) or not required_ids <= by_id.keys() \
            or not any(r.get('kind') == 'RAM' for r in regions):
        missing.append('MANDATORY_REGIONS_MISSING')
    if not flash_present and not record.get('flashReason'):
        missing.append('FLASH_APPLICABILITY_UNKNOWN')
    if not option_mapped and not record.get('optionReason'):
        missing.append('OPTION_APPLICABILITY_UNKNOWN')
    if not system_present and not record.get('systemReason'):
        missing.append('SYSTEM_APPLICABILITY_UNKNOWN')
    if not flash_present and any(r.get('kind') == 'FLASH' for r in regions):
        missing.append('FLASH_REGION_CONTRADICTS_AVAILABILITY')
    intervals = []
    for region in regions:
        start, size = region.get('start'), region.get('size')
        if not isinstance(start, int) or not isinstance(size, int) or size <= 0 or start < 0 \
                or start + size > 2**32:
            missing.append('INVALID_REGION_RANGE')
            continue
        if any(start < end and begin < start + size for begin, end in intervals):
            missing.append('PHYSICAL_BANK_OVERLAP')
        intervals.append((start, start + size))
        if region.get('configuration', 'FIXED') not in ('FIXED', 'ITCM_AXI_SHARED'):
            missing.append('INVALID_REGION_CONFIGURATION')
        shared = region.get('sharedAccess')
        if shared is not None and (not isinstance(shared, dict) or not shared
                                   or any(node not in ('cpu1', 'cpu2') or right not in ('r', 'rw')
                                          for node, right in shared.items())):
            missing.append('INVALID_SHARED_ACCESS')
    configuration = record.get('configurationAlternatives', {})
    if not isinstance(configuration, dict):
        missing.append('INVALID_CONFIGURATION_ALTERNATIVES')
        configuration = {}
    config_ids = set(configuration)
    declared_config = {r.get('configuration') for r in regions if r.get('configuration')}
    if not declared_config <= config_ids:
        missing.append('CONFIGURATION_UNDECLARED')
    for key, spec in configuration.items():
        allocations = spec.get('allocations') if isinstance(spec, dict) else None
        if not isinstance(spec, dict) or spec.get('kind') not in ('RAM', 'FLASH') \
                or not isinstance(spec.get('physicalKiB'), int) or spec.get('physicalKiB', 0) <= 0 \
                or not spec.get('reason') or not isinstance(allocations, dict) or not allocations:
            missing.append('INVALID_CONFIGURATION_ALTERNATIVES')
            continue
        for allocation_id, allocation in allocations.items():
            ranges = allocation.get('ranges') if isinstance(allocation, dict) else None
            if not isinstance(ranges, list) or not ranges:
                missing.append('INVALID_CONFIGURATION_ALTERNATIVES')
                continue
            total = 0
            spans = []
            for span in ranges:
                start, size = (span.get('start'), span.get('size')) if isinstance(span, dict) else (None, None)
                if not isinstance(start, int) or not isinstance(size, int) or size <= 0 \
                        or start < 0 or start + size > 2**32:
                    missing.append('INVALID_CONFIGURATION_ALTERNATIVES')
                else:
                    total += size
                    spans.append((start, size))
            if total != spec['physicalKiB'] * 1024:
                missing.append('CONFIGURATION_SIZE_MISMATCH')
            for index, (first_start, first_size) in enumerate(spans):
                for second_start, second_size in spans[index + 1:]:
                    if first_start < second_start + second_size \
                            and second_start < first_start + first_size:
                        missing.append('CONFIGURATION_RANGE_OVERLAP')
            for span_start, span_size in spans:
                for region in regions:
                    r_start, r_size = region.get('start'), region.get('size')
                    if not isinstance(r_start, int) or not isinstance(r_size, int):
                        continue
                    if span_start < r_start + r_size and r_start < span_start + span_size \
                            and region.get('configuration') != key:
                        missing.append('CONFIGURATION_RANGE_OVERLAP')
    for kind, field in [('RAM', 'ramKiB')]:
        capacity = record.get(field)
        declared = sum(region.get('size', 0) for region in regions
                       if region.get('kind') == kind)
        configured = sum(spec.get('physicalKiB', 0) * 1024 for key, spec in configuration.items()
                         if isinstance(spec, dict) and spec.get('kind') == kind)
        if not isinstance(capacity, int) or capacity <= 0 or declared + configured != capacity * 1024:
            missing.append('CAPACITY_CONFLICT_' + kind)
    if flash_present:
        capacity = record.get('flashKiB')
        if not isinstance(capacity, int) or capacity <= 0 or sum(
                region.get('size', 0) for region in regions if region.get('kind') == 'FLASH') \
                != capacity * 1024:
            missing.append('CAPACITY_CONFLICT_FLASH')
    if record.get('otpAvailability') not in ('UNAVAILABLE', 'AVAILABLE') or not record.get('otpReason') \
            or (record.get('otpAvailability') == 'AVAILABLE' and not any(r.get('kind') == 'OTP' for r in regions)):
        missing.append('OTP_APPLICABILITY_UNKNOWN')
    if not record.get('peripheralBitBandReason') or not record.get('sramBootRule'):
        missing.append('ALIAS_APPLICABILITY_UNKNOWN')
    if not record.get('sourceDocumentIds') or not record.get('sourceSections'):
        missing.append('DOCUMENT_PROVENANCE_MISSING')
    for alias in record.get('aliases', []) + record.get('bootAliases', []):
        target = by_id.get(alias.get('target'))
        if not target or alias.get('size') != target.get('size') \
                or alias.get('condition') not in ('ALWAYS', 'MAIN_FLASH', 'SYSTEM_MEMORY', 'SRAM') \
                or (alias.get('condition') != 'ALWAYS' and alias.get('start') != 0):
            missing.append('INVALID_BOOT_ALIAS')
    modes = {'MAIN_FLASH', 'SYSTEM_MEMORY'}
    if record.get('profile') != 'F103_MEDIUM_DENSITY_SINGLE_CORE':
        modes.add('SRAM')
    if record.get('bootAliasAvailability') == 'CONFIGURATION_DEPENDENT':
        if not record.get('bootAliasReason'):
            missing.append('BOOT_ALIAS_APPLICABILITY_UNKNOWN')
    elif {alias.get('condition') for alias in record.get('bootAliases', [])} != modes:
        missing.append('BOOT_VIEWS_MISSING')
    views = record.get('bitBandViews', [])
    ram = {r['id']: r for r in regions if r.get('kind') == 'RAM'}
    if record.get('bitBandAvailability') == 'UNAVAILABLE':
        if not record.get('bitBandReason'):
            missing.append('BIT_BAND_APPLICABILITY_UNKNOWN')
    else:
        if {v.get('target') for v in views} != set(ram) or len(views) != len(ram):
            missing.append('INVALID_BACKED_BIT_BAND')
        for view in views:
            target = ram.get(view.get('target'))
            bus = target.get('start') if target else None
            if bus == 0x10000000:
                bus = next((a.get('start') for a in record.get('aliases', [])
                            if a.get('target') == view.get('target')), None)
            if not target or bus is None:
                missing.append('INVALID_BACKED_BIT_BAND')
                continue
            if bus >= 0x40000000:
                expected = 0x42000000 + (bus - 0x40000000) * 32
            else:
                expected = 0x22000000 + (bus - 0x20000000) * 32
            if view.get('start') != expected or view.get('size') != target.get('size', 0) * 32:
                missing.append('INVALID_BACKED_BIT_BAND')
    topology = record.get('topology', {})
    required = ('core', 'instructionSet', 'languageId', 'compilerSpecId', 'bootRomContext',
                'securityDomain', 'resetHandlerAvailability', 'bootSelectionMechanism')
    strategy = topology.get('programStrategy')
    profile = record.get('profile', '')
    count = topology.get('physicalCoreCount')
    if count == 1:
        if strategy != 'SHARED_PROGRAM' or any(not topology.get(field) for field in required):
            missing.append('TOPOLOGY_INCOMPLETE')
        if '_DUAL_CORE' in profile:
            missing.append('PROFILE_CORE_COUNT_MISMATCH')
    elif count == 2:
        secondary = ('secondaryCore', 'secondaryInstructionSet', 'secondaryLanguageId',
                     'secondaryCompilerSpecId', 'secondaryBootMechanism')
        if strategy not in ('SHARED_PROGRAM', 'SEPARATE_PROGRAMS') \
                or any(not topology.get(field) for field in (*required, *secondary)):
            missing.append('TOPOLOGY_INCOMPLETE')
        if '_DUAL_CORE' not in profile:
            missing.append('PROFILE_CORE_COUNT_MISMATCH')
        for field in ('ipccRegisterRange', 'hsemRegisterRange'):
            bounds = topology.get(field)
            if not isinstance(bounds, list) or len(bounds) != 2 \
                    or not all(isinstance(bound, int) for bound in bounds) \
                    or bounds[0] < 0 or bounds[1] > 2**32 or bounds[0] >= bounds[1]:
                missing.append('INTER_PROCESSOR_RESOURCE_MISSING')
        for region in regions:
            if region.get('kind') == 'RAM' and not region.get('sharedAccess'):
                missing.append('SHARED_ACCESS_MISSING')
    else:
        missing.append('TOPOLOGY_INCOMPLETE')
    if record.get('supportState') != 'PLANNED' or profile not in REVIEWED_PROFILES:
        missing.append('UNREVIEWED_PROFILE_OR_PROMOTION')
    return sorted(set(missing))


def audit_catalog(path=CATALOG, plans_path=None):
    result = audit_bytes(Path(path).read_bytes())
    if plans_path is None:
        return result
    data = Path(plans_path).read_bytes()
    if sha256(data) != PLANS_SHA256:
        raise ValueError('STM32 memory plans digest mismatch')
    plans = json.loads(data)
    original = json.loads(Path(path).read_bytes())
    if plans.get('$schema') != 'urn:embedra:schema:stm32-memory-plans:1' \
            or plans.get('sourceCatalogSha256') != CATALOG_SHA256 \
            or plans.get('selectionSha256') != original.get('selectionSha256'):
        raise ValueError('STM32 memory plans source identity mismatch')
    records = plans.get('records', [])
    expected = {record['exactPart'] for record in original['records']}
    if len(records) != 53 or {record['exactPart'] for record in records} != expected:
        raise ValueError('STM32 memory plans exact selection mismatch')
    document_ids = {document['id'] for document in plans.get('sourceDocuments', [])}
    findings = {}
    for record in records:
        missing = plan_gaps(record)
        if not set(record.get('sourceDocumentIds', [])) <= document_ids:
            missing.append('SOURCE_DOCUMENT_UNKNOWN')
        if missing:
            findings[record['exactPart']] = missing
    result.update(memoryPlansSha256=PLANS_SHA256, readyCount=53-len(findings),
                  missingMemoryBanks=len(findings), incompleteParts=dict(sorted(findings.items())))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--require-complete', action='store_true',
                        help='Exit nonzero if any selected part lacks mandatory facts')
    args = parser.parse_args()
    result = audit_catalog(plans_path=PLANS)
    print(json.dumps(result, sort_keys=True, separators=(',', ':')))
    return int(args.require_complete and result['readyCount'] != result['recordCount'])


if __name__ == '__main__':
    raise SystemExit(main())
