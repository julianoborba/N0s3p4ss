from n0s3p4ss.header_validator import is_amazon_s3
from n0s3p4ss.header_validator import compare_nginx_version
from n0s3p4ss.report import ReportSchema, CertificateInformationsSchema
from n0s3p4ss.custom_json_logger import custom_logger
from n0s3p4ss.config import config
from n0s3p4ss.header_validator import is_ac_allow_origin_with_sameorigin, \
    is_x_xss_protection_mode_block
from n0s3p4ss.sec_headers_obtainer import retrieve_x_frame_options, \
    retrieve_strict_transport_security, retrieve_content_security_policy, \
    retrieve_x_content_type_options

CONFIG = config()


class ServerHeaderAnalyser:

    def apply(self, attack_surface):
        if not attack_surface.server_header:
            return get_default_report(attack_surface)

        alerts = ['Server disclosed!']

        comparison = compare_nginx_version(
            attack_surface.server_header,
            CONFIG.NGINX_SAFE_VERSION
        )
        if 'is lesser' in comparison:
            alerts.append(comparison)

        if is_amazon_s3(attack_surface.server_header):
            alerts.append('Bucket vulnerable to hijacking!')

        return ReportSchema().load(dict(
            subdomain=attack_surface.domain,
            url=attack_surface.response_url_location,
            ip=attack_surface.host,
            status=attack_surface.http_response.status_code,
            cert_info=CertificateInformationsSchema().load(dict()),
            server=attack_surface.server_header,
            tor=False,
            waf=[],
            open_ports=attack_surface.open_ports,
            alerts=alerts
        ))


class WebServerAnalyser:

    def apply(self, attack_surface):
        report = ServerHeaderAnalyser().apply(attack_surface)
        headers = attack_surface.get('http_response', {}).get('headers', {})
        alerts = []

        if not headers:
            alerts.append('No headers is present!')

        if not retrieve_x_frame_options(headers):
            alerts.append('"X-FRAME-OPTIONS" not present!')

        if not retrieve_strict_transport_security(headers):
            alerts.append('"Strict-transport-security" not present!')

        if 'SAMEORIGIN' not in is_ac_allow_origin_with_sameorigin(headers):
            alerts.append(is_ac_allow_origin_with_sameorigin(headers))

        if not retrieve_content_security_policy(headers):
            alerts.append('"Content-security-policy" not present!')

        if 'mode=block' not in is_x_xss_protection_mode_block(headers):
            alerts.append(is_x_xss_protection_mode_block(headers))

        if not retrieve_x_content_type_options(headers):
            alerts.append('"X-content-type-options" not present!')

        report['alerts'].extend(alerts)
        return report


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
        404: ServerHeaderAnalyser(),
        200: WebServerAnalyser()
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
        tor=False,
        waf=[],
        open_ports=attack_surface.open_ports,
        alerts=[]
    ))
