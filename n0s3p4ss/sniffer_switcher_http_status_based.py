from n0s3p4ss.header_validator import is_amazon_s3
from n0s3p4ss.header_validator import is_nginx_an_older_version
from n0s3p4ss.report import ReportSchema, CertificateInformationsSchema
from n0s3p4ss.config import config
from n0s3p4ss.header_validator import is_access_control_allow_origin_sameorigin
from n0s3p4ss.header_validator import is_cookie_path_slash
from n0s3p4ss.header_validator import is_cookie_http_only_present
from n0s3p4ss.header_validator import is_x_xss_protection_mode_block
from n0s3p4ss.sec_headers_obtainer import retrieve_x_frame_options
from n0s3p4ss.sec_headers_obtainer import retrieve_strict_transport_security
from n0s3p4ss.sec_headers_obtainer import retrieve_content_security_policy
from n0s3p4ss.sec_headers_obtainer import retrieve_x_content_type_options
from n0s3p4ss.ssl_analyser import SSLSocket
from n0s3p4ss.ssl_analyser import get_sslv23_method_context
from n0s3p4ss.ssl_analyser import get_ssl_connection
from n0s3p4ss.ssl_analyser import get_peer_certificate
from n0s3p4ss.ssl_analyser import get_cryptography_certificate
from n0s3p4ss.ssl_analyser import get_certificate_issuer
from n0s3p4ss.ssl_analyser import get_issuer_oid_common_name
from n0s3p4ss.ssl_analyser import load_certificate
from n0s3p4ss.ssl_analyser import get_cert_not_valid_after_attribute
from n0s3p4ss.ssl_analyser import get_server_certificate
from n0s3p4ss.ssl_analyser import get_cert_issuer
from n0s3p4ss.ssl_analyser import get_cert_not_after_attribute
from n0s3p4ss.tor_session_connector import TorSession
from n0s3p4ss.custom_json_logger import custom_logger
from requests.sessions import Session
from n0s3p4ss.waf_detector import detect
from datetime import datetime
from socket import AF_INET, SOCK_STREAM, socket
from idna import decode

CONFIG = config()

USER_AGENT = {
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_5) '
                  'AppleWebKit/537.36 (KHTML, like Gecko) '
                  'Chrome/50.0.2661.102 '
                  'Safari/537.36'
}


class ServerFingerprintingCollector:

    def apply(self, attack_surface):
        if not attack_surface.server_header:
            return get_default_report(attack_surface)

        alerts = ['Server disclosed!']

        if is_nginx_an_older_version(
                attack_surface.server_header,
                CONFIG.NGINX_SAFE_VERSION):
            alerts.append(
                f'The server Nginx version is lesser than Nginx expected '
                f'version; The expected version is {CONFIG.NGINX_SAFE_VERSION}'
            )

        if is_amazon_s3(attack_surface.server_header):
            alerts.append('Bucket vulnerable to hijacking!')

        return ReportSchema().load(dict(
            subdomain=attack_surface.domain,
            url=attack_surface.response_url_location,
            ip=attack_surface.host,
            status=attack_surface.http_response.status_code,
            cert_info=CertificateInformationsSchema().load(dict()),
            server=attack_surface.server_header,
            tor_reachable=False,
            detected_waf=[],
            open_ports=attack_surface.open_ports,
            alerts=alerts
        ))


class WebServerBannerGrabber:

    def apply(self, attack_surface):
        report = ServerFingerprintingCollector().apply(attack_surface)
        alerts = self.get_headers_info(attack_surface.http_response.headers)

        if 'https' in attack_surface.response_url_location:
            report['cert_info'] = \
                self.get_certificate_info(attack_surface.domain)
        else:
            alerts.append("HTTPS is not implemented!")

        if self.is_accessible_through_tor(attack_surface.domain):
            report['tor_reachable'] = True
            alerts.append('Domain accessible via TOR!')

        report['alerts'].extend(alerts)

        report['detected_waf'] = detect(attack_surface.domain)

        return report

    def get_headers_info(self, headers):
        alerts = []

        if not headers:
            alerts.append('No headers is present!')
            return alerts

        if not retrieve_x_frame_options(headers):
            alerts.append('"X-FRAME-OPTIONS" not present!')

        if not retrieve_strict_transport_security(headers):
            alerts.append('"Strict-transport-security" not present!')

        if not is_access_control_allow_origin_sameorigin(headers):
            alerts.append(
                '"Access Control Allow Origin" is not set as "SAMEORIGIN"!')

        if not retrieve_content_security_policy(headers):
            alerts.append(
                '"Content-security-policy" not present!')

        if not is_x_xss_protection_mode_block(headers):
            alerts.append('"X-XSS-protection" is not set as "mode=block"')

        if not retrieve_x_content_type_options(headers):
            alerts.append('"X-content-type-options" not present!')

        if is_cookie_path_slash(headers):
            alerts.append('Cookie flag "Path" defined as "/"!')

        if not is_cookie_http_only_present(headers):
            alerts.append('Cookie flag "HttpOnly" is not present!')

        return alerts

    def get_certificate_info(self, domain):
        with SSLSocket(
                domain, 443, socket(AF_INET, SOCK_STREAM)
        ) as ssl_socket:
            ssl_socket.connect()
            context = get_sslv23_method_context()
            ssl_connection = get_ssl_connection(
                context,
                ssl_socket.get_domain(),
                ssl_socket.get_socket()
            )

            cert_info = dict()

            if ssl_connection:
                ssl_connection.do_handshake()
                peer_cert = get_peer_certificate(ssl_connection)
                crypto_cert = get_cryptography_certificate(peer_cert)
                cert_issuer = get_certificate_issuer(crypto_cert)
                cert_info['issuer'] = get_issuer_oid_common_name(cert_issuer)
                expiration = get_cert_not_valid_after_attribute(crypto_cert)
                cert_info['expiration'] = expiration.strftime('%Y-%m-%d')

            if not cert_info:
                server_cert = get_server_certificate(domain, 443)

                if server_cert:
                    loaded_cert = load_certificate(server_cert)
                    cert_info['issuer'] = get_cert_issuer(loaded_cert)
                    expiration = get_cert_not_after_attribute(loaded_cert)
                    cert_info['expiration'] = datetime.strptime(
                        decode(expiration)[:-1], '%Y-%m-%d'
                    ).strftime('%Y-%m-%d')

            return CertificateInformationsSchema().load(cert_info)

    def is_accessible_through_tor(self, domain):
        with TorSession(Session(), USER_AGENT) as tor_session:
            response = tor_session.get(domain, 40)

            if not response:
                custom_logger.info(
                    f'domain {domain} get no response through TOR')
                return False

            if 200 == response.status_code \
                    or 'close' not in response.headers['connection']:
                return True
            elif 'captcha' in response.text \
                    or 'Access Denied' in response.text:
                custom_logger.info(
                    f'domain {domain} blocked access through TOR')
                return False

            custom_logger.info(
                f'domain {domain} is not accessible through TOR'
            )
            return False


class InvalidFlow:

    def apply(self, attack_surface):
        custom_logger.info(
            f'there\'s no analisys flow for HTTP status '
            f'{attack_surface.http_response.status_code} '
            f'incoming from subdomain {attack_surface.domain}'
        )
        return get_default_report(attack_surface)


def apply_flow_for(attack_surface):
    if not attack_surface:
        return get_default_report(attack_surface)

    switcher = {
        404: ServerFingerprintingCollector(),
        200: WebServerBannerGrabber()
    }

    return switcher.get(
        attack_surface.http_response.status_code,
        InvalidFlow()
    ).apply(attack_surface)


def get_default_report(attack_surface):
    return ReportSchema().load(dict(
        subdomain=attack_surface.domain,
        url=attack_surface.response_url_location,
        ip=attack_surface.host,
        status=attack_surface.http_response.status_code,
        cert_info=CertificateInformationsSchema().load(dict()),
        server=attack_surface.server_header,
        tor_reachable=False,
        detected_waf=[],
        open_ports=attack_surface.open_ports,
        alerts=[]
    ))
