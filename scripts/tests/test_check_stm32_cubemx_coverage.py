"""Bounded, aggregate-only CubeMX coverage diagnostics with synthetic inputs."""
import importlib.util
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
import zipfile

SCRIPT = Path(__file__).resolve().parents[1] / 'check-stm32-cubemx-coverage.py'
spec = importlib.util.spec_from_file_location('stm32_cubemx_coverage', SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

ATTRIBUTES = ['series', 'MXFILENAME_SDTDB', 'marketingStatus', 'die_id',
              'hasSecureBoot', 'securityFunctions', 'cryptography']
STM32_CLASS = 1734


def build_database(path, rows, attributes=ATTRIBUTES, extra_links=()):
    connection = sqlite3.connect(path)
    cursor = connection.cursor()
    cursor.execute('CREATE TABLE prmis_class (id integer PRIMARY KEY, '
                   'class_descr varchar(255) NOT NULL UNIQUE)')
    cursor.execute('CREATE TABLE cpn (id integer PRIMARY KEY, cpn varchar(45) '
                   'NOT NULL UNIQUE, refname TEXT, prmis_id INT)')
    cursor.execute('CREATE TABLE rpn (id integer PRIMARY KEY, rpn varchar(45) '
                   'NOT NULL UNIQUE, class_id integer NOT NULL, published integer, '
                   'publishingState varchar(45), marketingStatus varchar, '
                   'marketingRestriction varchar(45))')
    cursor.execute('CREATE TABLE rpn_has_cpn (rpn_id integer, cpn_id integer)')
    cursor.execute('CREATE TABLE attribute (id integer PRIMARY KEY, '
                   'name varchar(255) NOT NULL, sourceName varchar(255), '
                   'type varchar(45), unit varchar(45), description mediumtext, '
                   'prmis_id INT)')
    cursor.execute('CREATE TABLE rpn_has_attribute (rpn_id integer, '
                   'attribute_id integer, strValue varchar(1024), numValue double)')
    cursor.execute('CREATE TABLE cpn_has_attribute (cpn_id integer, '
                   'attribute_id integer, strValue varchar(1024), numValue double)')
    cursor.execute('CREATE TABLE version (id INTEGER, data_model_version TEXT, '
                   'configuration_version TEXT, latest_data_refresh DATETIME, '
                   'latest_pdsc DATETIME, tool_version TEXT)')
    cursor.execute('INSERT INTO prmis_class VALUES (1734, "STM32 32-bit Arm Cortex MCUs")')
    cursor.execute('INSERT INTO prmis_class VALUES (2319, "STM32 Arm Cortex MPUs")')
    for index, name in enumerate(attributes, start=1):
        cursor.execute('INSERT INTO attribute (id,name) VALUES (?,?)', (index, name))
    cursor.execute('INSERT INTO version VALUES (1,"2.1","3.0.42",0,0,"tool")')
    ids = {name: index for index, name in enumerate(attributes, start=1)}
    for rpn_id, (rpn, class_id, status, series) in enumerate(rows['rpns'], start=1):
        cursor.execute('INSERT INTO rpn (id,rpn,class_id,marketingStatus) '
                       'VALUES (?,?,?,?)', (rpn_id, rpn, class_id, status))
        cursor.execute('INSERT INTO rpn_has_attribute VALUES (?,?,?,NULL)',
                       (rpn_id, ids['series'], series))
    for cpn_id, (name, rpn_id, reference) in enumerate(rows['cpns'], start=1):
        cursor.execute('INSERT INTO cpn (id,cpn) VALUES (?,?)', (cpn_id, name))
        cursor.execute('INSERT INTO rpn_has_cpn VALUES (?,?)', (rpn_id, cpn_id))
        if reference is not None:
            cursor.execute('INSERT INTO cpn_has_attribute VALUES (?,?,?,NULL)',
                           (cpn_id, ids['MXFILENAME_SDTDB'], reference))
        cursor.execute('INSERT INTO cpn_has_attribute VALUES (?,?,?,NULL)',
                       (cpn_id, ids['marketingStatus'], rows['rpns'][rpn_id - 1][2]))
        cursor.execute('INSERT INTO cpn_has_attribute VALUES (?,?,?,NULL)',
                       (cpn_id, ids['die_id'], '0x123'))
    for rpn_id, cpn_id in extra_links:
        cursor.execute('INSERT INTO rpn_has_cpn VALUES (?,?)', (rpn_id, cpn_id))
    connection.commit()
    connection.close()


def build_archive(directory, rows=None, extra_links=()):
    rows = rows or {
        'rpns': [
            ('STM32F030C6', STM32_CLASS, 'Active', 'STM32F0'),
            ('STM32H745XI', STM32_CLASS, 'NRND', 'STM32H7'),
            ('STM32MP151A', 2319, 'Active', 'STM32MP1'),
        ],
        'cpns': [
            ('STM32F030C6T6', 1, 'STM32F030C6Tx'),
            ('STM32H745XIH6', 2, None),
            ('STM32MP151AAA3', 3, 'STM32MP151AAAx'),
            ('STM32F030C6T6TR', 1, 'STM32F030C6Tx'),
        ],
    }
    database = Path(directory) / 'cube-finder-db.db'
    build_database(database, rows, extra_links=extra_links)
    archive = Path(directory) / 'cube-finder-db.zip'
    with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as handle:
        handle.write(database, module.DB_MEMBER)
    return archive


def build_catalog(directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    source = {'records': [
        {'id': 'STM32F030C6Tx', 'family': 'STM32F0'},
        {'id': 'STM32F030C8Tx', 'family': 'STM32F0'},
        {'id': 'STM32MP151AAAx', 'family': 'STM32MP1'},
    ]}
    c5 = {'parts': [{'exactPart': 'STM32C531CBT6',
                     'sourceElement': 'device/STM32C531CB/variant/STM32C531CBT6'}]}
    (directory / 'source-catalog.json').write_text(json.dumps(source))
    (directory / 'c5-exact-parts.json').write_text(json.dumps(c5))
    return directory


class CoverageTests(unittest.TestCase):
    def test_reconciles_counts_and_series(self):
        with tempfile.TemporaryDirectory() as folder:
            catalog = build_catalog(Path(folder) / 'catalog')
            archive = build_archive(Path(folder))
            report = module.build_report(catalog, archive)
            totals = report['coverage']['totals']
            self.assertEqual(totals['vendorCommercialParts'], 4)
            self.assertEqual(totals['vendorExactParts'], 3)
            self.assertEqual(totals['vendorWildcardParts'], 1)
            self.assertEqual(totals['vendorReferenceProducts'], 3)
            self.assertEqual(totals['vendorPartsMatchingEmbedraReferencePattern'], 3)
            self.assertEqual(totals['embedraReferencePatterns'], 3)
            self.assertEqual(totals['embedraExactParts'], 1)
            self.assertEqual(totals['vendorPartsWithDieId'], 4)
            self.assertEqual(report['cubemx']['productClasses'],
                             ['STM32 32-bit Arm Cortex MCUs', 'STM32 Arm Cortex MPUs'])
            series = {row['series']: row for row in report['coverage']['vendorSeries']}
            self.assertEqual(series['STM32F0']['commercialParts'], 2)
            self.assertEqual(series['STM32H7']['wildcardParts'], 1)
            self.assertEqual(report['coverage']['gaps']['vendorSeriesAbsentFromEmbedra'],
                             ['STM32H7'])

    def test_report_is_deterministic_and_aggregate_only(self):
        with tempfile.TemporaryDirectory() as folder:
            catalog = build_catalog(Path(folder) / 'catalog')
            archive = build_archive(Path(folder))
            first = module.canonical(module.build_report(catalog, archive))
            second = module.canonical(module.build_report(catalog, archive))
            self.assertEqual(first, second)
            for forbidden in (b'STM32F030C6T6', b'0x123', b'cube-finder-db.db'):
                self.assertNotIn(forbidden, first)

    def test_missing_archive_reports_embedra_only(self):
        with tempfile.TemporaryDirectory() as folder:
            catalog = build_catalog(Path(folder) / 'catalog')
            report = module.build_report(catalog, None)
            self.assertIsNone(report['coverage'])
            self.assertEqual(report['embedraFamilies'], {'STM32F0': 2, 'STM32MP1': 1})
            self.assertEqual(report['embedraExactPartsBySeries'], {'STM32C5': 1})

    def test_unreadable_and_malformed_inputs_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)
            catalog = build_catalog(folder / 'catalog')
            archive = build_archive(folder)
            broken = folder / 'broken.zip'
            broken.write_bytes(b'not a zip')
            with self.assertRaisesRegex(module.CoverageError, 'unreadable'):
                module.build_report(catalog, broken)
            partial = folder / 'partial.zip'
            with zipfile.ZipFile(partial, 'w') as handle:
                handle.writestr('unexpected.db', b'x')
            with self.assertRaisesRegex(module.CoverageError, 'unexpected database'):
                module.build_report(catalog, partial)

    def test_schema_and_duplicate_guards(self):
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)
            catalog = build_catalog(folder / 'catalog')
            empty = folder / 'empty.db'
            sqlite3.connect(empty).close()
            archive = folder / 'empty.zip'
            with zipfile.ZipFile(archive, 'w') as handle:
                handle.write(empty, module.DB_MEMBER)
            with self.assertRaisesRegex(module.CoverageError, 'schema is incomplete'):
                module.build_report(catalog, archive)
            duplicate = build_archive(folder, extra_links=[(2, 1)])
            with self.assertRaisesRegex(module.CoverageError, 'duplicate'):
                module.build_report(catalog, duplicate)

    def test_missing_catalog_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaisesRegex(module.CoverageError, 'missing or unsafe'):
                module.build_report(Path(folder), None)

    def test_compare_reports(self):
        current = {'coverage': {
            'totals': {'embedraReferencePatterns': 10, 'vendorCommercialParts': 5},
            'vendorSeries': [{'series': 'STM32F0'}, {'series': 'STM32V8'}]}}
        baseline = {'coverage': {
            'totals': {'embedraReferencePatterns': 9, 'vendorCommercialParts': 4},
            'vendorSeries': [{'series': 'STM32F0'}]}}
        changes = module.compare_reports(current, baseline)
        self.assertEqual(changes['addedVendorSeries'], ['STM32V8'])
        self.assertEqual(changes['removedVendorSeries'], [])
        self.assertEqual(changes['embedraReferencePatternDelta'], 1)
        self.assertEqual(changes['vendorCommercialPartDelta'], 1)

    def test_committed_catalog_without_archive(self):
        catalog_dir = SCRIPT.parents[1] / 'catalogs/stm32/2026-09-28'
        report = module.build_report(catalog_dir, None)
        self.assertEqual(sum(report['embedraFamilies'].values()), 2240)
        self.assertEqual(sum(report['embedraExactPartsBySeries'].values()), 157)
        self.assertEqual(
            module.sha256((catalog_dir / 'source-catalog.json').read_bytes()),
            report['embedra']['sourceCatalogSha256'])
        self.assertEqual(
            module.canonical(report),
            module.canonical(module.build_report(catalog_dir, None)))


if __name__ == '__main__':
    unittest.main()
