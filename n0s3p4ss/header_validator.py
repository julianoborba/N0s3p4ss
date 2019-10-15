from packaging import version
from n0s3p4ss.sec_headers_obtainer import retrieve_x_xss_protection, \
    retrieve_access_control_allow_origin, retrieve_set_cookie


def is_amazon_s3(server_header):
    return 'AmazonS3' in server_header


def compare_nginx_version(server_header, nginx_version_number):
    server_header_parts = server_header.split('nginx/')
    if len(server_header_parts) < 2:
        return ''

    server_version = server_header_parts[1]

    if version.parse(server_version) < version.parse(nginx_version_number):
        return (f'The server Nginx version is lesser than Nginx expected '
                f'version; The expected version is {nginx_version_number}')

    return ('The server Nginx version is the same as the expected Nginx '
            f'version; The expected version is {nginx_version_number}')


def is_ac_allow_origin_with_sameorigin(headers={}):
    ac_allow_origin = retrieve_access_control_allow_origin(headers)
    if not ac_allow_origin:
        return ''

    if ac_allow_origin != 'SAMEORIGIN':
        return (f'"Allow-origin" present with value: '
                f'{ac_allow_origin}')

    return '"Allow-origin" present with value: SAMEORIGIN'


def is_x_xss_protection_mode_block(headers={}):
    x_xss_protection = retrieve_x_xss_protection(headers)

    if not x_xss_protection:
        return ''

    if 'mode=block' not in x_xss_protection:
        return '"X-XSS-protection" is not set as "mode=block"'

    return '"X-XSS-protection" is set as "mode=block"'


def is_cookie_path_denifed_as_slash(headers={}):
    set_cookie = retrieve_set_cookie(headers)

    if not set_cookie:
        return ''

    if 'path=/' in set_cookie:
        return '"Path" defined as "/"'

    return '"Path" not defined as "/"'


def is_cookie_http_only_defined(headers={}):
    set_cookie = retrieve_set_cookie(headers)

    if not set_cookie:
        return ''

    if 'HttpOnly' not in set_cookie:
        return '"HttpOnly" is not present'

    return '"HttpOnly" is present'
