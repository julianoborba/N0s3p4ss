from n0s3p4ss.config import config

CONFIG = config()


class TorSession:

    def __enter__(self):
        return self

    def __init__(self, session, user_agent):
        self._user_agent = user_agent
        self._tor_session = session
        self._tor_session.proxies = CONFIG.TOR_SESSION_PROXIES

    def get(self, url, timeout):
        return self._tor_session.get(
            f'http://{url}',
            headers=self._user_agent,
            verify=False,
            timeout=timeout
        )

    def close(self):
        self._tor_session.close()

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
