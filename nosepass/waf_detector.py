from wafw00f.main import WafW00F
from nosepass.config import config

CONFIG = config()


def detect(url):
    wafw00f = WafW00F(
        target=url,
        proxy=CONFIG.WAFW00F_PROXY
    )
    return wafw00f.identwaf(True)
