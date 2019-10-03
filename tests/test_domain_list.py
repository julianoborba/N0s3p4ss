from unittest import TestCase
from unittest.mock import patch
from nosepass.domain_list import SubdomainList
from concurrent.futures import ThreadPoolExecutor, TimeoutError


class DomainListTest(TestCase):

    @patch.object(SubdomainList, 'list_subdomains')
    def test_that_should_get_subdomains_from_domains(self, list_subdomains):
        expected_subdomains = [
            'www.grupozap.com', 'www.vivareal.com',
            'www.grupozap.com', 'www.vivareal.com'
        ]
        list_subdomains.return_value = ['www.grupozap.com', 'www.vivareal.com']

        current_subdomains = SubdomainList().list_each_domain_subdomains(
            ['grupozap.com', 'vivareal.com'],
        )

        self.assertEqual(expected_subdomains, current_subdomains)

    @patch.object(SubdomainList, 'list_subdomains')
    @patch.object(ThreadPoolExecutor, 'map', side_effect=TimeoutError)
    def test_that_should_raise_timeout_exception(self,
                                                 list_subdomains,
                                                 thread_pool_executor):
        list_subdomains.return_value = ['www.grupozap.com', 'www.vivareal.com']

        current_subdomains = SubdomainList().list_each_domain_subdomains(
            ['zapimoveis.com', 'vivareal.com']
        )

        self.assertEqual([], current_subdomains)

    def test_that_should_return_empty_list(self):
        empty_subdomains = SubdomainList().list_each_domain_subdomains(None)

        self.assertEqual([], empty_subdomains)
