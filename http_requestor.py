from requests.sessions import Session
from custom_json_logger import getLogger

USER_AGENT = {
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_5) '
                  'AppleWebKit/537.36 (KHTML, like Gecko) '
                  'Chrome/50.0.2661.102 '
                  'Safari/537.36'
}

PROXIES = {
    'http': 'http://18.229.145.152:8888',
    'https': 'http://18.229.145.152:8888'
}


def do_get(url):
    try:
        with Session() as session:
            return session.get(
                headers=USER_AGENT,
                proxies=PROXIES,
                timeout=10,
                url='https://www.google.com',
                verify=False
            )
    except ConnectionError as connection_error:
        getLogger().error(
            'ConnectionError for %s, cause %s',
            url,
            connection_error,
            exc_info=1
        )
        return None
