from requests.sessions import Session
from requests.exceptions import HTTPError, ConnectionError, ReadTimeout
from requests.models import Response
from n0s3p4ss.custom_json_logger import custom_logger
from n0s3p4ss.config import config

CONFIG = config()

IS_ENABLED = True


def do_get(url):
    try:
        with Session() as session:
            response = session.get(
                headers=CONFIG.HTTP_SESSION_HEADERS,
                proxies=CONFIG.HTTP_SESSION_PROXIES,
                timeout=10,
                url=f'http://{url}',
                verify=False
            )
            response.raise_for_status()
            return response

    except HTTPError as http_error:
        response = Response()
        response.status_code = http_error.response.status_code
        return response

    except ConnectionError as connection_error:
        custom_logger.error(
            f'ConnectionError for {url}, cause {connection_error}',
            exc_info=IS_ENABLED
        )
        response = Response()
        response.status_code = 503
        return response
    except ReadTimeout as timeout_error:
        custom_logger.error(
            f'ReadTimeout for {url}, cause {timeout_error}',
            exc_info=IS_ENABLED
        )
        response = Response()
        response.status_code = 408
        return response
