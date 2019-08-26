from unittest import TestCase
from ports_analyser import get_ports_from_nmap_scan_dictionary, \
                        retrieve_open_ports


class PortsAnalyserTest(TestCase):

    def test_that_should_format_list_from_scan(self):
        ports_info = {80: {'status': 'open', 'address': '150.5.7.1'},
                      8080: {'status': 'closed', 'address': '127.0.0.1'}}

        self.assertEqual({80: 'open', 8080: 'closed'},
                         get_ports_from_nmap_scan_dictionary(ports_info))

    def test_that_should_detect_subdomain_has_open_ports(self):
        ports = {80: 'open', 8080: 'open', 5000: 'closed'}

        self.assertEqual([80, 8080], retrieve_open_ports(ports))

    def test_that_should_detect_subdomain_has_not_open_ports(self):
        ports = {22: 'closed', 23: 'closed', 21: 'closed'}

        self.assertEqual([], retrieve_open_ports(ports))
