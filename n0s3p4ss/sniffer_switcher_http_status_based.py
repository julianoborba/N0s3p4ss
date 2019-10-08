from n0s3p4ss.server_header_comparator import is_amazon_s3
from n0s3p4ss.server_header_comparator import compare_nginx_version
from n0s3p4ss.report import ReportSchema, CertificateInformationsSchema
from n0s3p4ss.custom_json_logger import custom_logger
from n0s3p4ss.config import config

CONFIG = config()


class HTTP404Flow:

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
        404: HTTP404Flow()
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
