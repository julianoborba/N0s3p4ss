from n0s3p4ss.config import config
from n0s3p4ss.custom_json_logger import custom_logger

CONFIG = config()
IS_ENABLED = True


class TorSession:

    def __enter__(self):
        return self

    def __init__(self, session, user_agent):
        self._user_agent = user_agent
        self._tor_session = session
        self._tor_session.proxies = CONFIG.TOR_SESSION_PROXIES

    def get(self, url, timeout):
        try:
            return self._tor_session.get(
                f'http://{url}',
                headers=self._user_agent,
                verify=False,
                timeout=timeout
            )
        except ConnectionError as connection_error:
            custom_logger.error(
                f'ConnectionError for {url}, cause {connection_error}',
                exc_info=IS_ENABLED
            )
        return None

    def close(self):
        self._tor_session.close()

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
