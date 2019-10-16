from packaging import version
from n0s3p4ss.sec_headers_obtainer import retrieve_x_xss_protection, \
    retrieve_access_control_allow_origin, retrieve_set_cookie


def is_amazon_s3(server_header):
    return 'AmazonS3' in server_header


def is_nginx_an_older_version(server_header, expected_version):
    header_parts = server_header.split('nginx/') if server_header else []
    return len(header_parts) >= 2 and (
            version.parse(header_parts[1]) <
            version.parse(expected_version)
    )


def is_access_control_allow_origin_sameorigin(headers):
    return 'SAMEORIGIN' in retrieve_access_control_allow_origin(headers)


def is_x_xss_protection_mode_block(headers):
    return 'mode=block' in retrieve_x_xss_protection(headers)


def is_cookie_path_slash(headers):
    return 'path=/' in retrieve_set_cookie(headers)


def is_cookie_http_only_present(headers):
    return 'HttpOnly' in retrieve_set_cookie(headers)
