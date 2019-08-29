class TorSession:

    def __init__(self, session, user_agent):
        self._user_agent = user_agent
        self._tor_session = session
        self._tor_session.proxies = {
            'http': 'socks5://127.0.0.1:9150',
            'https': 'socks5://127.0.0.1:9150'
        }

    def get(self, url):
        return self._tor_session.get(
            url,
            headers=self._user_agent,
            verify=False,
            timeout=20
        )

    def close(self):
        self._tor_session.close()
