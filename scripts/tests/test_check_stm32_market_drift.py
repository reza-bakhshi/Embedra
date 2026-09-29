"""A current exact-page or status change requires catalog review."""
import importlib.util
from pathlib import Path
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'check-stm32-market-drift.py'
spec = importlib.util.spec_from_file_location('stm32_market_drift', SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class DriftTests(unittest.TestCase):
    def test_exact_status_and_missing_page(self):
        selected = {'$schema': 'urn:embedra:schema:stm32-curated-selection:2',
                    'parts': [{'exactPart': 'STM32F401RET6',
                               'selectionReason': 'CURRENT_ST_NUCLEO_OR_DISCOVERY_EXACT_CPN',
                               'marketingStatus': 'ACTIVE',
                               'stockStatusOnSelectionDate': 'IN_STOCK'}]}
        live = {'$schema': 'urn:embedra:schema:stm32-estore-audit:1',
                'checkedDate': '2026-09-30',
                'rows': [{'exactPart': 'STM32F401RET6', 'result': 'PARSED',
                          'marketingStatus': 'ACTIVE', 'stockStatus': 'IN_STOCK'}]}
        self.assertEqual(module.compare(selected, live)['status'], 'PASS')
        live['rows'][0]['stockStatus'] = 'OUT_OF_STOCK'
        self.assertEqual(module.compare(selected, live)['changes'][0]['reason'], 'STATUS_CHANGED')
        live['rows'][0]['result'] = 'FETCH_FAILED'
        self.assertEqual(module.compare(selected, live)['changes'][0]['reason'], 'CURRENT_PAGE_UNVERIFIED')

if __name__ == '__main__':
    unittest.main()
