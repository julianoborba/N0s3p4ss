from unittest import TestCase
from unittest.mock import patch
from requests.models import Response
from requests.sessions import Session
from nosepass.attack_surface_discoverer import discover, HostAttackSurface


class AttackSurfaceDiscovererTest(TestCase):
    _nmap_scan_result = {
        'nmap': {
            'command_line': 'nmap -oX - -sV 107.178.254.45',
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
            '107.178.254.45': {
                'hostnames': [{'name': 'localhost', 'type': 'PTR'}],
                'addresses': {'ipv4': '107.178.254.45'},
                'vendor': {},
                'status': {'state': 'up', 'reason': 'conn-refused'},
                'tcp': {
                    3306: {
                        'state': 'open',
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

    @patch('nmap.PortScanner.scan')
    @patch('nosepass.attack_surface_discoverer.get_host_by_name')
    @patch.object(Session, 'get')
    def test_that_should_obtain_domain_surface_info(self,
                                                    get,
                                                    get_host_by_name,
                                                    scan):
        response = Response()
        response.status_code = 200
        response.url = 'https://www.grupozap.com:443/'
        response.headers = {'Server': 'openresty'}
        get.return_value = response
        get_host_by_name.return_value = '107.178.254.45'
        scan.return_value = self._nmap_scan_result

        expected_discover_results = HostAttackSurface(
            domain='www.grupozap.com',
            http_response=response,
            server_header='openresty',
            response_url_location='https://www.grupozap.com:443/',
            host='107.178.254.45',
            open_ports=[3306]
        )

        discover_results = discover('www.grupozap.com')

        self.assertEquals(expected_discover_results, discover_results)
