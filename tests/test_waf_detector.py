from unittest import TestCase
from unittest.mock import patch
from waf_detector import detect
from wafw00f import main


class WAFDetectorTest(TestCase):

    @patch.object(main.WafW00F, 'identwaf')
    def test_that_should_detect_waf(self, identwaf):
        identwaf.return_value = ['Cloudflare (Cloudflare Inc.)']

        waf_list = detect('www.vivareal.com.br', 443, True)

        self.assertIsNotNone(waf_list)
        self.assertEqual(['Cloudflare (Cloudflare Inc.)'], waf_list)
