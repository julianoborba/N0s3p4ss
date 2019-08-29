from unittest import TestCase
from unittest.mock import patch
from ports_analyser import get_ports_only_from_nmap_scan, \
    retrieve_open_ports, scan_ports_with_nmap


class PortsAnalyserTest(TestCase):
    _nmap_scan_result = {
        'nmap': {
            'command_line': 'nmap -oX - -sV 127.0.0.1',
            'scaninfo': {
                'tcp': {
                    'method': 'connect',
                    'services': '1,3-4,6-7,9,13,17'
                }
            },
            'scanstats': {
                'timestr': 'Tue Aug 27 14:59:25 2019',
                'elapsed': '21.46',
                'uphosts': '1',
                'downhosts': '0',
                'totalhosts': '1'
            }
        },
        'scan': {
            '127.0.0.1': {
                'hostnames': [{'name': 'localhost', 'type': 'PTR'}],
                'addresses': {'ipv4': '127.0.0.1'},
                'vendor': {},
                'status': {'state': 'up', 'reason': 'conn-refused'},
                'tcp': {
                    631: {
                        'state': 'open',
                        'reason': 'syn-ack',
                        'name': 'ipp',
                        'product': 'CUPS',
                        'version': '2.2',
                        'extrainfo': '',
                        'conf': '10',
                        'cpe': 'cpe:/a:apple:cups:2.2'
                    },
                    3306: {
                        'state': 'close',
                        'reason': 'syn-ack',
                        'name': 'mysql',
                        'product': '',
                        'version': '',
                        'extrainfo': '',
                        'conf': '3',
                        'cpe': ''}
                }
            }
        }
    }

    def test_that_should_get_ports_only_from_nmap_scan(self):
        self.assertEqual(
            {
                631: 'open',
                3306: 'close'
            },
            get_ports_only_from_nmap_scan(
                self._nmap_scan_result,
                '127.0.0.1'
            )
        )

    def test_that_should_retrieve_open_ports_only(self):
        ports = {
            80: 'open',
            8080: 'open',
            5000: 'closed'
        }

        self.assertEqual([80, 8080], retrieve_open_ports(ports))

    def test_that_should_not_retrieve_open_ports(self):
        ports = {
            22: 'closed',
            23: 'closed',
            21: 'closed'
        }

        self.assertEqual([], retrieve_open_ports(ports))

    @patch('nmap.PortScanner.scan')
    def test_that_should_scan_ports_with_nmap(self, scan):
        scan.return_value = self._nmap_scan_result
        host = '127.0.0.1'

        scan_result = scan_ports_with_nmap(host)

        scan.assert_called_once_with(host)
        self.assertEqual(
            'open',
            scan_result['scan']['127.0.0.1']['tcp'][631]['state']
        )
        self.assertEqual(
            'close',
            scan_result['scan']['127.0.0.1']['tcp'][3306]['state']
        )
