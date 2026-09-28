#!/usr/bin/env python3
"""Compare committed STM32 catalog facts against a local STM32CubeMX Finder DB.

This tool is a coverage diagnostic, not a catalog generator. It never copies
vendor rows, part numbers, memory values, die IDs, or database bytes into any
committed artifact. Output contains aggregate counts and ST-authored series
labels only. The local CubeMX database carries SLA0048 processing-unit terms
and must not be redistributed or used to produce the shipped catalog.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import sys
import tempfile
import zipfile

SCHEMA = 'urn:embedra:schema:stm32-cubemx-coverage:1'
GENERATOR = 'embedra-stm32-cubemx-coverage-v1'
DEFAULT_CATALOG_DIR = Path('catalogs/stm32/2026-09-28')
DB_MEMBER = 'cube-finder-db.db'
PRODUCT_CLASSES = ('STM32 32-bit Arm Cortex MCUs', 'STM32 Arm Cortex MPUs')
REFERENCE_ATTRIBUTE = 'MXFILENAME_SDTDB'
SECURITY_ATTRIBUTES = ('hasSecureBoot', 'securityFunctions', 'cryptography')
MAX_ARCHIVE_BYTES = 200_000_000
MAX_DB_BYTES = 400_000_000
MAX_ROWS = 200_000


class CoverageError(ValueError):
    pass


def canonical(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=False,
                       separators=(',', ':')) + '\n').encode()


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def canonical_series(series):
    """Normalize ST series labels for set comparison only.

    The ST reference-product ``series`` attribute groups the WL family under one
    ``STM32WL`` label, while the pinned pin-data snapshot keeps ``STM32WL``,
    ``STM32WL3``, and ``STM32WL4`` apart; ``L4`` and ``L4+`` also appear
    separately. Collapsing them here avoids reporting naming differences as
    coverage gaps.
    """
    value = series[:-1] if series.endswith('+') else series
    if value in ('STM32WL', 'STM32WL3', 'STM32WL4'):
        return 'STM32WL'
    return value


def series_from_part(part):
    match = re.match(r'STM32(MP[0-9]|WB0|WBA|WB|WL[0-9]?|[A-Z][0-9])', part)
    return 'STM32' + match.group(1) if match else 'UNKNOWN'


def load_embedra_catalog(directory):
    source_path = directory / 'source-catalog.json'
    exact_path = directory / 'c5-exact-parts.json'
    if source_path.is_symlink() or not source_path.is_file():
        raise CoverageError('committed source catalog is missing or unsafe')
    if exact_path.is_symlink() or not exact_path.is_file():
        raise CoverageError('committed exact-part catalog is missing or unsafe')
    source_bytes = source_path.read_bytes()
    exact_bytes = exact_path.read_bytes()
    source = json.loads(source_bytes)
    exact = json.loads(exact_bytes)
    records = source.get('records')
    parts = exact.get('parts')
    if not isinstance(records, list) or not records:
        raise CoverageError('invalid committed source catalog')
    if not isinstance(parts, list) or not parts:
        raise CoverageError('invalid committed exact-part catalog')
    if len(records) > MAX_ROWS or len(parts) > MAX_ROWS:
        raise CoverageError('committed catalog exceeds row limit')
    patterns = {}
    families = {}
    for record in records:
        identifier = record.get('id')
        family = record.get('family')
        if not isinstance(identifier, str) or not isinstance(family, str):
            raise CoverageError('invalid committed source record')
        patterns[identifier] = family
        families[family] = families.get(family, 0) + 1
    exact_parts = {}
    for part in parts:
        exact_part = part.get('exactPart')
        if not isinstance(exact_part, str):
            raise CoverageError('invalid committed exact part')
        exact_parts[exact_part] = series_from_part(exact_part)
    return {
        'sourceSha256': sha256(source_bytes),
        'exactSha256': sha256(exact_bytes),
        'patterns': patterns,
        'families': families,
        'exactParts': exact_parts,
    }


def read_member_bounded(archive, member, limit):
    if member.file_size > limit:
        raise CoverageError(f'oversized database member: {member.file_size}')
    digest = hashlib.sha256()
    total = 0
    handle = tempfile.NamedTemporaryFile(delete=False)
    try:
        with archive.open(member) as source:
            while True:
                chunk = source.read(1 << 20)
                if not chunk:
                    break
                total += len(chunk)
                if total > limit:
                    raise CoverageError('database member exceeds byte limit')
                digest.update(chunk)
                handle.write(chunk)
    except BaseException:
        handle.close()
        Path(handle.name).unlink(missing_ok=True)
        raise
    handle.close()
    return Path(handle.name), digest.hexdigest(), total


def open_database(zip_path):
    if zip_path.is_symlink() or not zip_path.is_file():
        raise CoverageError('CubeMX archive is missing or unsafe')
    if zip_path.stat().st_size > MAX_ARCHIVE_BYTES:
        raise CoverageError('CubeMX archive exceeds byte limit')
    try:
        archive = zipfile.ZipFile(zip_path)
    except (zipfile.BadZipFile, OSError) as exc:
        raise CoverageError(f'unreadable CubeMX archive: {exc}') from exc
    with archive:
        members = [m for m in archive.infolist()
                   if m.filename == DB_MEMBER]
        if len(members) != 1:
            raise CoverageError('unexpected database members in CubeMX archive')
        database_path, digest, size = read_member_bounded(
            archive, members[0], MAX_DB_BYTES)
    try:
        connection = sqlite3.connect(f'file:{database_path}?mode=ro', uri=True)
        connection.execute('PRAGMA quick_check').fetchone()
    except sqlite3.DatabaseError as exc:
        database_path.unlink(missing_ok=True)
        raise CoverageError(f'unreadable CubeMX database: {exc}') from exc
    return connection, database_path, {
        'archiveSha256': sha256(zip_path.read_bytes()),
        'databaseSha256': digest,
        'databaseBytes': size,
    }


def attribute_id(cursor, name):
    row = cursor.execute('SELECT id FROM attribute WHERE name=?', (name,)).fetchone()
    return row[0] if row else None


def verify_schema(cursor):
    tables = {row[0] for row in cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    required = {'cpn', 'rpn', 'rpn_has_cpn', 'attribute',
                'rpn_has_attribute', 'cpn_has_attribute', 'prmis_class', 'version'}
    if not required.issubset(tables):
        raise CoverageError('CubeMX database schema is incomplete')
    row = cursor.execute(
        'SELECT data_model_version, configuration_version, tool_version FROM version'
    ).fetchone()
    return row or (None, None, None)


def vendor_rows(cursor, class_ids):
    if len(class_ids) > 32:
        raise CoverageError('too many product classes')
    id_placeholders = ','.join('?' for _ in class_ids)
    series_attribute = attribute_id(cursor, 'series')
    reference_attribute = attribute_id(cursor, REFERENCE_ATTRIBUTE)
    status_attribute = attribute_id(cursor, 'marketingStatus')
    die_attribute = attribute_id(cursor, 'die_id')
    security_ids = [value for value in
                    (attribute_id(cursor, name) for name in SECURITY_ATTRIBUTES)
                    if value is not None]

    reference_series = {}
    for series_label, rpn_count in cursor.execute(f"""
            SELECT ra.strValue, COUNT(DISTINCT r.id)
            FROM rpn r
            JOIN rpn_has_attribute ra ON ra.rpn_id=r.id AND ra.attribute_id=?
            WHERE r.class_id IN ({id_placeholders})
            GROUP BY ra.strValue""",
            [series_attribute] + class_ids):
        reference_series[series_label or 'UNKNOWN'] = rpn_count

    rows = cursor.execute(f"""
        SELECT c.id, c.cpn, r.marketingStatus,
               (SELECT ra.strValue FROM rpn_has_attribute ra
                 WHERE ra.rpn_id=r.id AND ra.attribute_id=?)
        FROM cpn c
        JOIN rpn_has_cpn rc ON rc.cpn_id=c.id
        JOIN rpn r ON r.id=rc.rpn_id
        WHERE r.class_id IN ({id_placeholders})""",
        [series_attribute] + class_ids).fetchall()
    if not rows or len(rows) > MAX_ROWS:
        raise CoverageError('CubeMX STM32 row count outside limit')
    if len({row[1] for row in rows}) != len(rows):
        raise CoverageError('duplicate CubeMX commercial part numbers')

    def single_values(attribute):
        if attribute is None:
            return {}
        result = {}
        for cpn_id, value in cursor.execute(
                'SELECT cpn_id, strValue FROM cpn_has_attribute WHERE attribute_id=?',
                (attribute,)):
            if cpn_id not in result and value:
                result[cpn_id] = value
        return result

    reference_by_cpn = single_values(reference_attribute)
    status_by_cpn = single_values(status_attribute)
    die_by_cpn = single_values(die_attribute)
    security = set()
    for attribute in security_ids:
        security.update(cpn_id for cpn_id, _ in cursor.execute(
            'SELECT cpn_id, strValue FROM cpn_has_attribute WHERE attribute_id=?',
            (attribute,)))
    return [{
        'cpn': row[1],
        'series': row[3] or 'UNKNOWN',
        'status': status_by_cpn.get(row[0]) or row[2] or 'Unknown',
        'reference': reference_by_cpn.get(row[0]),
        'dieId': row[0] in die_by_cpn,
        'security': row[0] in security,
    } for row in rows], reference_series


def summarize(vendor, reference_series, embedra):
    reference_set = set(embedra['patterns'])
    series = {}
    for label, count in reference_series.items():
        series[label] = {
            'referenceProducts': count, 'commercialParts': 0, 'exactParts': 0,
            'wildcardParts': 0, 'withReferencePattern': 0,
            'matchingEmbedraReferencePattern': 0, 'withDieId': 0,
            'withSecurityAttribute': 0, 'lifecycle': {},
        }
    lifecycle = {}
    with_reference = 0
    matching_reference = 0
    exact = 0
    wildcard = 0
    with_die = 0
    with_security = 0
    attested = set()
    for row in vendor:
        bucket = series.setdefault(row['series'], {
            'referenceProducts': 0, 'commercialParts': 0, 'exactParts': 0,
            'wildcardParts': 0, 'withReferencePattern': 0,
            'matchingEmbedraReferencePattern': 0, 'withDieId': 0,
            'withSecurityAttribute': 0, 'lifecycle': {},
        })
        bucket['commercialParts'] += 1
        bucket['lifecycle'][row['status']] = bucket['lifecycle'].get(row['status'], 0) + 1
        lifecycle[row['status']] = lifecycle.get(row['status'], 0) + 1
        if re.search(r'[xX]', row['cpn']):
            wildcard += 1
            bucket['wildcardParts'] += 1
        else:
            exact += 1
            bucket['exactParts'] += 1
        if row['reference']:
            with_reference += 1
            bucket['withReferencePattern'] += 1
            if row['reference'] in reference_set:
                matching_reference += 1
                bucket['matchingEmbedraReferencePattern'] += 1
                attested.add(row['reference'])
        if row['dieId']:
            with_die += 1
            bucket['withDieId'] += 1
        if row['security']:
            with_security += 1
            bucket['withSecurityAttribute'] += 1
    embedra_exact_series = exact_series_counts(embedra['exactParts'])
    vendor_series = set(reference_series) | set(series)
    embedra_series = {canonical_series(f) for f in embedra['families']}
    embedra_series |= {canonical_series(s) for s in embedra_exact_series}
    return {
        'totals': {
            'vendorReferenceProducts': sum(reference_series.values()),
            'vendorCommercialParts': len(vendor),
            'vendorExactParts': exact,
            'vendorWildcardParts': wildcard,
            'vendorPartsWithReferencePattern': with_reference,
            'vendorPartsMatchingEmbedraReferencePattern': matching_reference,
            'vendorPartsWithDieId': with_die,
            'vendorPartsWithSecurityAttribute': with_security,
            'embedraReferencePatterns': len(reference_set),
            'embedraReferencePatternsAttestedByVendor': len(attested),
            'embedraReferencePatternsUnattested': len(reference_set - attested),
            'embedraExactParts': len(embedra['exactParts']),
        },
        'vendorLifecycle': lifecycle,
        'vendorSeries': [dict(series=name, **series[name]) for name in sorted(series)],
        'embedraFamilies': dict(sorted(embedra['families'].items())),
        'embedraExactPartsBySeries': dict(sorted(embedra_exact_series.items())),
        'gaps': {
            'vendorSeriesAbsentFromEmbedra': sorted(
                s for s in vendor_series if canonical_series(s) not in embedra_series),
            'embedraSeriesAbsentFromVendor': sorted(
                s for s in embedra_series
                if s not in {canonical_series(v) for v in vendor_series}),
            'unattestedReferencePatterns': sorted(reference_set - attested),
        },
    }


def build_report(catalog_dir, zip_path):
    embedra = load_embedra_catalog(catalog_dir)
    report = {
        '$schema': SCHEMA,
        'generator': GENERATOR,
        'embedra': {
            'sourceCatalogSha256': embedra['sourceSha256'],
            'exactCatalogSha256': embedra['exactSha256'],
        },
    }
    if zip_path is None:
        report['cubemx'] = None
        report['coverage'] = None
        report['notes'] = ['No CubeMX archive supplied; vendor comparison unavailable.']
        report['embedraFamilies'] = dict(sorted(embedra['families'].items()))
        report['embedraExactPartsBySeries'] = exact_series_counts(embedra['exactParts'])
        return report
    connection, database_path, digests = open_database(zip_path)
    try:
        cursor = connection.cursor()
        version = verify_schema(cursor)
        placeholders = ','.join('?' for _ in PRODUCT_CLASSES)
        classes = cursor.execute(
            f'SELECT id, class_descr FROM prmis_class WHERE class_descr IN ({placeholders})',
            PRODUCT_CLASSES).fetchall()
        if len(classes) != len(PRODUCT_CLASSES):
            raise CoverageError('STM32 product classes are missing from CubeMX database')
        vendor, reference_series = vendor_rows(cursor, [row[0] for row in classes])
    finally:
        connection.close()
        database_path.unlink(missing_ok=True)
    report['cubemx'] = {
        'archiveSha256': digests['archiveSha256'],
        'databaseSha256': digests['databaseSha256'],
        'databaseBytes': digests['databaseBytes'],
        'dataModelVersion': version[0],
        'configurationVersion': version[1],
        'toolVersion': version[2],
        'productClasses': sorted(row[1] for row in classes),
    }
    report['coverage'] = summarize(vendor, reference_series, embedra)
    report['notes'] = [
        'Aggregate coverage diagnostic only; no vendor rows, part numbers, '
        'memory values, die IDs, or database bytes are emitted.',
        'The local CubeMX Finder database is SLA0048-restricted and must not be '
        'redistributed or used to build the shipped catalog.',
        'A vendor commercial part number is not promoted to an exact Embedra '
        'part by this report.',
    ]
    return report


def exact_series_counts(exact_parts):
    result = {}
    for series_name in exact_parts.values():
        result[series_name] = result.get(series_name, 0) + 1
    return dict(sorted(result.items()))


def compare_reports(current, baseline):
    old = baseline.get('coverage') or {}
    new = current.get('coverage') or {}
    old_series = {row['series'] for row in old.get('vendorSeries', [])}
    new_series = {row['series'] for row in new.get('vendorSeries', [])}
    old_totals = old.get('totals', {})
    new_totals = new.get('totals', {})
    return {
        'addedVendorSeries': sorted(new_series - old_series),
        'removedVendorSeries': sorted(old_series - new_series),
        'embedraReferencePatternDelta': (
            new_totals.get('embedraReferencePatterns', 0)
            - old_totals.get('embedraReferencePatterns', 0)),
        'vendorCommercialPartDelta': (
            new_totals.get('vendorCommercialParts', 0)
            - old_totals.get('vendorCommercialParts', 0)),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--catalog-dir', type=Path, default=DEFAULT_CATALOG_DIR)
    parser.add_argument('--cubemx-zip', type=Path)
    parser.add_argument('--baseline', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    try:
        report = build_report(args.catalog_dir, args.cubemx_zip)
        if args.baseline is not None:
            report['changes'] = compare_reports(
                report, json.loads(args.baseline.read_bytes()))
        data = canonical(report)
        if args.output is not None:
            args.output.write_bytes(data)
        totals = report.get('coverage', {}).get('totals') if report.get('coverage') else {}
        print(f'STM32 CubeMX coverage: {json.dumps(totals, sort_keys=True)}')
        return 0
    except (CoverageError, OSError, KeyError, TypeError, ValueError,
            json.JSONDecodeError) as exc:
        print(f'STM32 coverage: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
