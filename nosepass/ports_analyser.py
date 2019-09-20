from nmap import PortScanner
from nosepass.custom_json_logger import getLogger


def scan_ports_with_nmap(host):
    scanner = PortScanner()
    return scanner.scan(host)


def get_ports_only_from_nmap_scan(scan, host):
    if host not in scan['scan']:
        getLogger().error(
            'host %s not found in nmap scan',
            host,
            exc_info=1
        )
        return {}
    ports = (scan['scan'][host]['tcp']).copy()
    for port, attributes in ports.items():
        ports.update({port: attributes['state']})
    return ports


def retrieve_open_ports(ports):
    if not ports:
        return []
    return [
        port for port, state in ports.items()
        if state == 'open'
    ]
