"""Compatibility matrix integrity and anti-drift tests (T075).

Verifies that docs/compatibility-matrix.md contains no unearned promotion and
exactly matches the repository truth: catalog record counts and support
states, pack inventory, target-provider topologies, the build baseline, and
the Java hardware-crypto catalog. Offline only: reads repository files and
performs no network or subprocess work.
"""
import json
import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
MATRIX = REPO / 'docs' / 'compatibility-matrix.md'
SPECKIT = REPO / 'Embedra-SpecKit.md'
STATE = REPO / '.embedra' / 'state.json'
ESP_CATALOG = REPO / 'catalogs' / 'espressif' / '2026-09-23' / 'catalog.json'
RP_CATALOG = REPO / 'catalogs' / 'rp' / '2026-10-02' / 'catalog.json'
RP_BOARDS = REPO / 'catalogs' / 'rp' / '2026-10-02' / 'board-profiles.json'
STM32_CATALOG = REPO / 'catalogs' / 'stm32' / '2026-09-29' / 'curated-catalog.json'
BUILDSL = REPO / 'build.gradle'

STATES = {'PLANNED', 'EXPERIMENTAL', 'VERIFIED', 'UNSUPPORTED'}

# Parsers the T071 deterministic format-fuzz framework covers; every one must
# be real code on disk and documented in the input-format matrix.
FORMAT_PARSERS = (
    'EspImageParser',
    'Esp8266ImageParser',
    'RpUf2Parser',
    'Stm32DfuParser',
    'Stm32VectorDiscovery',
    'EspPartitionTableDiscovery',
    'RpBootMetadataParser',
)

JAVA_DIR = REPO / 'src' / 'main' / 'java' / 'io' / 'github' / 'rezabakhshi' / 'embedra'
CRYPTO_DIR = JAVA_DIR / 'analyzers' / 'crypto'
ESP_SERIES_DISPLAY = {
    'esp8266Legacy': 'ESP8266 (legacy, ESP8266EX/ESP8285)',
    'esp32s2': 'ESP32-S2',
    'esp32s3': 'ESP32-S3',
    'esp32s31': 'ESP32-S31',
}
KEYWORDS_SECTION_7 = (
    'aes', 'sha', 'rsa', 'trng', 'secure boot', 'flash encryption',
    'efuse', 'secp256k1', 'curve25519', 'p-256',
)


def read_text(path):
    return path.read_text(encoding='utf-8')


def esp_series_display(key):
    """Map a state.json targetProviders key to the matrix's series label."""
    if key in ESP_SERIES_DISPLAY:
        return ESP_SERIES_DISPLAY[key]
    if key.startswith('esp32') and len(key) > len('esp32'):
        return 'ESP32-' + key[len('esp32'):].upper()
    return key.upper()


def esp_series_row(table, key, column):
    """Find an ESP series row by display name, aliases, or prefix match."""
    name = esp_series_display(key)
    name_i = table['header'].index('Series')
    for row in table['rows']:
        if row[name_i] == name:
            return row
    for row in table['rows']:
        if row[name_i].startswith(name + ' ('):
            return row
    raise AssertionError(f'{key} ({name}) missing from the ESP series table')


def extract_fact_block(text):
    """Return the machine-readable facts dictionary from the matrix."""
    for raw in re.findall(r'```json\n(.*?)```', text, flags=re.DOTALL):
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if {'espressif', 'packs', 'deviceSupportState'} <= set(data):
            return data
    raise AssertionError('compatibility matrix is missing the machine-readable facts block')


def matrix_tables(text):
    """Group pipe rows into tables keyed by their header cells."""
    tables = []
    current = None
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith('|'):
            cells = [c.strip() for c in stripped.strip('|').split('|')]
            if all(set(c) <= set('-: ') for c in cells):  # separator row
                continue
            if current is None or len(cells) != len(current['header']):
                current = {'header': cells, 'rows': []}
                tables.append(current)
                continue
            current['rows'].append(cells)
        else:
            current = None
    return tables


def find_table(tables, columns):
    """Locate a table by an exact ordered subset of its header columns."""
    for table in tables:
        if all(col in table['header'] for col in columns):
            return table
    raise AssertionError(f'table with columns {columns} missing from matrix')


def parse_state_cell(value):
    """Extract the leading support-state token from a State column cell."""
    return value.split(' (', 1)[0].strip()


class CompatibilityMatrixIntegrity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.matrix = read_text(MATRIX)
        cls.facts = extract_fact_block(cls.matrix)
        cls.state = json.loads(read_text(STATE))
        cls.esp = json.loads(read_text(ESP_CATALOG))
        cls.rp = json.loads(read_text(RP_CATALOG))
        cls.rp_boards = json.loads(read_text(RP_BOARDS))
        cls.stm32 = json.loads(read_text(STM32_CATALOG))
        cls.speckit = read_text(SPECKIT)
        cls.tables = matrix_tables(cls.matrix)

    # ------------------------------------------------------------ fact block
    def test_fact_block_counts_match_espressif_catalog(self):
        records = self.esp['records']
        esp = self.facts['espressif']
        self.assertEqual(esp['siliconRecords'],
                         sum(1 for r in records if r['kind'] == 'SILICON'))
        self.assertEqual(esp['moduleProfiles'],
                         sum(1 for r in records if r['kind'] == 'MODULE'))
        self.assertEqual(esp['boardProfiles'],
                         sum(1 for r in records if r['kind'] == 'BOARD'))
        self.assertEqual(esp['series'],
                         len({r['series'] for r in records if r['kind'] == 'SILICON'}))

    def test_fact_block_counts_match_rp_catalog_and_boards(self):
        rp = self.facts['raspberryPi']
        self.assertEqual(rp['siliconRecords'], len(self.rp['records']))
        self.assertEqual(rp['boardProfiles'], len(self.rp_boards['profiles']))

    def test_fact_block_counts_match_stm32_curated_catalog(self):
        records = self.stm32['records']
        stm = self.facts['stm32']
        self.assertEqual(stm['curatedParts'], len(records))
        self.assertEqual(stm['subfamilies'], len({r['family'] for r in records}))
        computed = {}
        for record in records:
            for proc in record['processors']:
                computed[proc['core']] = computed.get(proc['core'], 0) + 1
        self.assertEqual(stm['coreCounts'], computed)
        self.assertEqual(sum(computed.values()), len(records))

    def test_fact_block_device_support_matches_catalog_records(self):
        """No unearned promotion: every catalog record must agree with the
        documented device-support state per vendor."""
        declared = self.facts['deviceSupportState']
        esp_states = set()
        for record in self.esp['records']:
            esp_states.update(record['supportStates'].values())
        rp_states = {r['supportState'] for r in self.rp['records']}
        rp_states.update(b['supportState'] for b in self.rp_boards['profiles'])
        stm_states = {r['supportState'] for r in self.stm32['records']}
        for vendor, states in (
                ('espressif', esp_states),
                ('raspberryPi', rp_states),
                ('stm32', stm_states)):
            self.assertTrue(states.isdisjoint({'VERIFIED', 'EXPERIMENTAL'}),
                            f'{vendor} catalog records earned a promotion without notice')
            self.assertEqual(states, {declared[vendor]},
                             f'{vendor} catalog records must all be {declared[vendor]}')

    def test_pack_counts_match_packs_directory(self):
        dirs = sorted(p.name for p in (REPO / 'packs').iterdir() if p.is_dir())
        counts = {'svd': 0, 'rom': 0, 'peripherals': 0, 'signatures': 0}
        for name in dirs:
            if name.endswith('.svd'):
                counts['svd'] += 1
            elif name.endswith('.rom'):
                counts['rom'] += 1
            elif name.endswith('.peripherals'):
                counts['peripherals'] += 1
            elif name.endswith('.signatures'):
                counts['signatures'] += 1
            else:
                self.fail(f'unclassified pack directory {name!r}; classify it and update the facts block')
        declared = self.facts['packs']
        for key, value in counts.items():
            self.assertEqual(declared[key], value, f'packs.{key} count drift')
        self.assertEqual(declared['total'], len(dirs))

    def test_provider_pack_expectations_match_materialized_packs(self):
        """Pack materialization must match the ESP series table: unavailable
        enrichment providers own no packs; documented SVD targets own SVD
        packs; the legacy ESP8266 family owns nothing in the ESP registry."""
        pack_dirs = set(p.name for p in (REPO / 'packs').iterdir() if p.is_dir())
        legacy_in_registry = [d for d in pack_dirs if 'esp8266' in d]
        self.assertFalse(legacy_in_registry, legacy_in_registry)
        for key, provider in self.state['targetProviders'].items():
            if key == 'esp8266Legacy':
                continue
            rom = f'espressif.{key}.rom'
            peripherals = f'espressif.{key}.peripherals'
            svd = f'espressif.{key}.svd'
            unavailable = provider.get('enrichmentStatus') == 'UNAVAILABLE_IN_PINNED_SOURCES'
            if unavailable:
                self.assertNotIn(rom, pack_dirs, key)
                self.assertNotIn(peripherals, pack_dirs, key)
                self.assertNotIn(svd, pack_dirs, key)
                continue
            self.assertIn(rom, pack_dirs, key)
            self.assertIn(peripherals, pack_dirs, key)
            # SVD expectation comes from the matrix's pack-coverage column,
            # which is anchored to state.json in the series-table test.
            table = find_table(self.tables, ['Series', 'Processor topology'])
            name_i, pack_i = table['header'].index('Series'), table['header'].index('Pack coverage')
            packcell = esp_series_row(table, key, pack_i)[pack_i]
            if 'UNAVAILABLE_IN_PINNED_SOURCE' in packcell:
                self.assertNotIn(svd, pack_dirs, key)
            elif 'SVD' in packcell:
                self.assertIn(svd, pack_dirs, key)

    # -------------------------------------------------------------- baseline
    def test_baseline_matches_build_gradle_and_state(self):
        build = read_text(BUILDSL)
        self.assertIn('requiredJava = JavaVersion.VERSION_21', build)
        self.assertIn("requiredGhidraVersion = '12.1.3'", build)
        baseline = self.facts['baseline']
        self.assertEqual(baseline['ghidraRelease'], '12.1.3')
        self.assertEqual(baseline['javaVersion'], '21')
        self.assertEqual(self.state['toolchains']['ghidra']['version'], '12.1.3')
        self.assertEqual(self.state['toolchains']['java']['requiredBaseline'], '21')

    def test_jdk_rejection_is_documented(self):
        self.assertIn('JDK 25', self.matrix)
        self.assertIn('Embedra requires JDK 21', self.matrix)

    def test_host_os_support_rows(self):
        table = find_table(self.tables, ['Dimension', 'Exact value'])
        state_col, value_col = table['header'].index('State'), table['header'].index('Exact value')
        states = {row[value_col]: parse_state_cell(row[state_col]) for row in table['rows']}
        self.assertEqual(states['Linux x86-64'], 'VERIFIED')
        self.assertEqual(states['Windows x86-64'], 'VERIFIED')
        self.assertEqual(states['macOS x86-64'], 'VERIFIED')
        self.assertEqual(states['macOS ARM64'], 'VERIFIED')
        self.assertEqual(states['Linux non-x86-64 (ARM, RISC-V hosts), 32-bit hosts'],
                         'UNSUPPORTED')
        self.assertEqual(states['12.1.3 PUBLIC (2026-08-17, revision `8b4c91d4d5bd1549622bfbade0df199585b98365`)'],
                         'VERIFIED')

    # ------------------------------------------------------ state vocabulary
    def test_support_state_vocabulary_matches_speckit(self):
        for token in sorted(STATES):
            self.assertIn(f'| `{token}` |', self.speckit)

    def test_every_table_state_cell_is_a_single_vocabulary_token(self):
        checked = 0
        for table in self.tables:
            if 'State' not in table['header']:
                continue
            col = table['header'].index('State')
            for row in table['rows']:
                self.assertLessEqual(col, len(row) - 1,
                                     f'ragged row in table {table["header"]}: {row}')
                state = parse_state_cell(row[col])
                self.assertIn(state, STATES,
                              f'off-vocabulary state token {state!r} in row {row[0]!r}')
                self.assertNotIn('/', parse_state_cell(row[col]) + row[col])
                checked += 1
        self.assertGreater(checked, 90, 'matrix must contain substantive state rows')

    # --------------------------------------------------------- device tables
    def test_esp_series_table_matches_provider_states_and_topologies(self):
        table = find_table(self.tables, ['Series', 'Processor topology'])
        header = table['header']
        name_i, topo_i = header.index('Series'), header.index('Processor topology')
        state_i = header.index('Workflow state')
        device_i = header.index('Device-support state')
        providers = self.state['targetProviders']
        for key, provider in providers.items():
            row = esp_series_row(table, key, name_i)
            if provider.get('processorTopology'):
                self.assertTrue(row[topo_i].startswith(f'`{provider["processorTopology"]}`'),
                                f'{key} topology drift vs state.json')
            self.assertEqual(parse_state_cell(row[device_i]), 'PLANNED',
                             f'{key} exact records must stay PLANNED')
            self.assertIn(parse_state_cell(row[state_i]), STATES)
        # ESP32-S3 topology comes from the T074 catalog contract (dual-core
        # Xtensa, applicationCoreCount 2); the token is documented locally
        # until the T080 series refresh pins a provider topology token.
        s3_topo = esp_series_row(table, 'esp32s3', name_i)[topo_i]
        self.assertIn('Two symmetric LX7 application cores', s3_topo)
        esp_catalog = json.loads(read_text(ESP_CATALOG))
        s3_records = [r for r in esp_catalog['records']
                      if r['kind'] == 'SILICON' and r['series'] == 'ESP32-S3']
        self.assertTrue(all(r['applicationCoreCount'] == 2 and r['isa'] == 'XTENSA'
                            for r in s3_records))
        legacy = esp_series_row(table, 'esp8266Legacy', name_i)
        self.assertTrue(legacy[topo_i].startswith(
            f'`{providers["esp8266Legacy"]["processorTopology"]}`'))

    def test_stm32_subfamily_table_matches_catalog(self):
        table = find_table(self.tables, ['Subfamily', 'Parts'])
        counted = {}
        for row in table['rows']:
            counted[row[0]] = int(row[1])
            self.assertEqual(parse_state_cell(row[3]), 'PLANNED',
                             f'{row[0]} device support must stay PLANNED')
        catalog = {}
        for record in self.stm32['records']:
            catalog[record['family']] = catalog.get(record['family'], 0) + 1
        self.assertEqual(counted, catalog)
        self.assertEqual(sum(catalog.values()), 53)

    def test_rp_silicon_table_states_match_catalog(self):
        table = find_table(self.tables, ['Silicon part', 'Device-support state'])
        col = table['header'].index('Device-support state')
        parts = {row[0]: parse_state_cell(row[col]) for row in table['rows']}
        expected = {record['exactPart']: record['supportState']
                    for record in self.rp['records']}
        self.assertEqual(parts, expected)

    def test_rp_board_profiles_tabulated(self):
        table = find_table(self.tables, ['Board profile', 'Silicon link'])
        pre_i, link_i = table['header'].index('Board profile'), table['header'].index('Silicon link')
        linked = {row[pre_i].strip('`'): row[link_i] for row in table['rows']}
        expected = {profile['profileId']: profile['siliconPart']
                    for profile in self.rp_boards['profiles']}
        self.assertEqual(linked, expected)

    def test_device_support_invariants_stated_in_prose(self):
        self.assertIn('All 53 curated STM32 part records remain `PLANNED`', self.matrix)
        self.assertIn('device-support states of the exact catalog records remain `PLANNED`',
                      self.matrix)
        self.assertIn('Every one of the 272 records carries', self.matrix)
        self.assertIn('all records `PLANNED` per RP-002', self.matrix)

    # ---------------------------------------------------------------- formats
    def test_format_parsers_exist_and_are_documented(self):
        names = {p.stem for p in JAVA_DIR.rglob('*.java')}
        for parser in FORMAT_PARSERS:
            self.assertIn(parser, names, f'{parser} missing from the source tree')
            self.assertIn(f'`{parser}`', self.matrix,
                          f'{parser} missing from the input-format matrix')
        self.assertIn('DTB binary', self.matrix)
        self.assertIn('70,000 total', self.matrix)
        self.assertIn('10,000 deterministic malformed inputs', self.matrix)

    # ---------------------------------------------------------- crypto catalog
    def test_hardware_crypto_catalog_counts_match_java(self):
        catalog = read_text(CRYPTO_DIR / 'hardware' / 'HardwareCryptoCatalog.java')
        declared = self.facts['hardwareCryptoCatalog']
        self.assertEqual(declared['peripheralRegisters'], catalog.count('regs.add'))
        self.assertEqual(declared['vendorRomRoutines'], catalog.count('roms.add'))
        self.assertEqual(declared['secureElements'], catalog.count('ses.add'))
        self.assertEqual(declared['platforms'],
                         self._count_enum_constants('HardwareCryptoPlatform'))
        self.assertEqual(declared['features'],
                         self._count_enum_constants('HardwareCryptoFeature'))
        self.assertEqual(declared['detectorSubsystems'],
                         self._count_enum_constants('CryptoDetectorType'))

    def _count_enum_constants(self, enum_name):
        for path in CRYPTO_DIR.rglob(f'{enum_name}.java'):
            text = read_text(path)
            block = re.search(rf'enum {enum_name} \{{(.*?)\n\}}', text, re.DOTALL)
            if block:
                return len(re.findall(r'^ {4}[A-Z_0-9]+\(', block.group(1), re.MULTILINE))
        raise AssertionError(f'enum {enum_name} not found')

    def test_detector_subsystem_names_are_documented(self):
        names = re.findall(r'^ {4}([A-Z_0-9]+)\(',
                           read_text(CRYPTO_DIR / 'corpus' / 'CryptoDetectorType.java'),
                           re.MULTILINE)
        self.assertTrue(names)
        for name in names:
            self.assertIn(f'`{name}`', self.matrix,
                          f'detector subsystem {name} missing from matrix section 7')

    def test_required_crypto_algorithm_coverage(self):
        """AES, SHA, RSA, ECC, RNG, secure boot, flash encryption all covered."""
        section7 = self.matrix.split('## 7.', 1)[1].split('## 8.', 1)[0].lower()
        for token in KEYWORDS_SECTION_7:
            self.assertIn(token, section7, f'section 7 lacks coverage of {token}')
        catalog = read_text(CRYPTO_DIR / 'hardware' / 'HardwareCryptoCatalog.java')
        for token in ('CryptoAlgorithm.RSA', 'CryptoAlgorithm.SHA256',
                      'CryptoAlgorithm.TRNG', 'CryptoAlgorithm.FLASH_ENCRYPTION',
                      'CryptoAlgorithm.SECURE_BOOT', 'CryptoAlgorithm.ECC_P256',
                      'CryptoAlgorithm.ECDSA'):
            self.assertIn(token, catalog)

    def test_matrix_section_headers_cover_every_required_dimension(self):
        for heading in ('## 2. Espressif', '## 3. Raspberry Pi', '## 4. STM32',
                        '## 5. Input formats', '## 6. Enrichment packs',
                        '## 7. Hardware-crypto detectors',
                        '## 8. Program feature states'):
            self.assertIn(heading, self.matrix)


if __name__ == '__main__':
    unittest.main()
