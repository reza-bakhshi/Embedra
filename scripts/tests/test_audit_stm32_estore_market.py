"""ST eStore audit parser accepts only exact page identities and statuses."""
import importlib.util
from pathlib import Path
import unittest
SCRIPT = Path(__file__).resolve().parents[1] / 'audit-stm32-estore-market.py'
spec = importlib.util.spec_from_file_location('stm32_market', SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class MarketTests(unittest.TestCase):
    def test_exact_page_and_status(self):
        html = b'<p data-tooltip-text="Product is in volume production.">Active</p><h1 class="page-title">STM32F401RET6</h1><div class="stock available"><span><strong>In stock</strong></span></div>'
        self.assertEqual(module.parse('STM32F401RET6', html),
                         {'result':'PARSED','marketingStatus':'ACTIVE','stockStatus':'IN_STOCK'})
        self.assertEqual(module.parse('STM32F401RET7', html)['result'], 'PAGE_IDENTITY_UNVERIFIED')

    def test_missing_or_unavailable_status(self):
        html = b'<h1 class="page-title">STM32F401RET6</h1><div class="stock unavailable"><span><strong>Out of stock</strong></span></div>'
        self.assertEqual(module.parse('STM32F401RET6', html)['stockStatus'], 'OUT_OF_STOCK')
        self.assertEqual(module.parse('STM32F401RET6', html)['result'], 'INCOMPLETE_PAGE')
        html += b'<p data-tooltip-text="Product is in volume production.">Active</p>'
        self.assertEqual(module.parse('STM32F401RET6', html)['result'], 'PARSED')
        self.assertEqual(module.parse('STM32F401RET6', html.replace(b'<strong>', b'').replace(b'</strong>', b''))['stockStatus'], 'OUT_OF_STOCK')

if __name__ == '__main__': unittest.main()
