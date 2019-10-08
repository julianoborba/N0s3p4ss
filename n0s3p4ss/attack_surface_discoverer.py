from n0s3p4ss.custom_json_logger import custom_logger
from n0s3p4ss.http_requestor import do_get
from n0s3p4ss.ports_analyser import \
    scan_ports_with_nmap, \
    get_ports_only_from_nmap_scan, \
    retrieve_open_ports
from socket import gethostbyname
from dataclasses import dataclass
from requests.models import Response

IS_ENABLED = True


def get_host_by_name(domain):
    try:
        return gethostbyname(domain)
    except Exception as socket_error:
        custom_logger.error(
            f'an error occurred while trying to get host'
            f' by name from domain {domain}, cause {socket_error}',
            exc_info=IS_ENABLED
        )
        return ''


@dataclass
class HostAttackSurface:
    domain: str
    http_response: Response
    server_header: str
    response_url_location: str
    host: str
    open_ports: list


def discover(domain):
    response = do_get(domain)
    server = response.headers.get('Server', '')
    url = response.url if response.url else ''
    host = get_host_by_name(domain)

    open_ports = []
    if host:
        nmap_result = scan_ports_with_nmap(host)
        ports = get_ports_only_from_nmap_scan(nmap_result, host)
        open_ports = retrieve_open_ports(ports)

    return HostAttackSurface(
        domain=domain,
        http_response=response,
        server_header=server,
        response_url_location=url,
        host=host,
        open_ports=open_ports
    )
