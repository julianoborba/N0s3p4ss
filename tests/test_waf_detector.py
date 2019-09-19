from unittest import TestCase
from unittest.mock import patch
from nosepass.waf_detector import detect
from wafw00f.main import WafW00F


class WAFDetectorTest(TestCase):

    @patch.object(WafW00F, 'identwaf')
    def test_that_should_detect_waf(self, identwaf):
        identwaf.return_value = ['Cloudflare (Cloudflare Inc.)']

        waf_list = detect('www.vivareal.com.br')

        self.assertIsNotNone(waf_list)
        self.assertEqual(['Cloudflare (Cloudflare Inc.)'], waf_list)
