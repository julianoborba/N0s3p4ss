def retrieve_x_frame_options(headers):
    return headers.get('X-Frame-Options')


def retrieve_strict_transport_security(headers):
    return headers.get('Strict-Transport-Security')


def retrieve_access_control_allow_origin(headers):
    return headers.get('Access-Control-Allow-Origin')


def retrieve_content_security_policy(headers):
    return headers.get('Content-Security-Policy')


def retrieve_x_xss_protection(headers):
    return headers.get('X-XSS-Protection')


def retrieve_x_content_type_options(headers):
    return headers.get('X-Content-Type-Options')


def retrieve_set_cookie(headers):
    return headers.get('Set-Cookie')
