class TorSession:

    def __enter__(self):
        return self

    def __init__(self, session, user_agent):
        self._user_agent = user_agent
        self._tor_session = session
        self._tor_session.proxies = {
            'http': 'socks5://127.0.0.1:9150',
            'https': 'socks5://127.0.0.1:9150'
        }

    def get(self, url, timeout):
        return self._tor_session.get(
            url,
            headers=self._user_agent,
            verify=False,
            timeout=timeout
        )

    def close(self):
        self._tor_session.close()

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
