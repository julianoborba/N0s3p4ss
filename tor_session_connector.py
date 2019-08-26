

class TorSession:

    def __init__(self, session, user_agent):
        self.user_agent = user_agent
        self.tor_session = session
        self.tor_session.proxies = {
            'http': 'socks5://127.0.0.1:9150',
            'https': 'socks5://127.0.0.1:9150'}

    def get(self, url):
        return self.tor_session.get(url, headers=self.user_agent,
                                    verify=False, timeout=20)

    def close(self):
        self.tor_session.close()
