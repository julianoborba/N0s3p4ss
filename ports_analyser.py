from nmap import PortScanner


def scan_ports_with_nmap(host):
    scanner = PortScanner()
    return scanner.scan(host)


def get_ports_only_from_nmap_scan(scan, host):
    ports = (scan['scan'][host]['tcp']).copy()
    for port, attributes in ports.items():
        ports.update({port: attributes['state']})
    return ports


def retrieve_open_ports(ports):
    return [
        port for port, state in ports.items()
        if state == 'open'
    ]
