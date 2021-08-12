from wafw00f.main import WafW00F
from n0s3p4ss.config import config

CONFIG = config()


def detect(url):
    wafw00f = WafW00F(
        target=url,
        proxies=CONFIG.HTTP_SESSION_PROXIES
    )
    return wafw00f.identwaf(True)
