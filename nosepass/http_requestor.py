from requests.sessions import Session
from requests.exceptions import HTTPError, ConnectionError
from requests.models import Response
from nosepass.custom_json_logger import getLogger
from nosepass.config import config

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
        getLogger().error(
            f'ConnectionError for {url}, cause {connection_error}',
            exc_info=IS_ENABLED
        )
        return Response()
