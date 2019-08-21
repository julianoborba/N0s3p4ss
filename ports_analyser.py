from nmap import PortScanner


def scan_ports_with_nmap(host):
    scanner = PortScanner()
    scanner.scan(host)
    return scanner[host]['tcp']


def get_ports_from_nmap_scan_dictionary(ports_information):
    ports = {}
    for current_port, attributes in ports_information.items():
        ports.update({current_port: attributes['status']})
    return ports


def retrieve_open_ports(ports_with_status):
    return [port for port, status in ports_with_status.items()
            if status == 'open']
