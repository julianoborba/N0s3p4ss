import os

PROD = 'production'
DEV = 'development'
TEST = 'test'


class Config(object):
    HTTP_SESSION_HEADERS = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_5) '
                      'AppleWebKit/537.36 (KHTML, like Gecko) '
                      'Chrome/50.0.2661.102 '
                      'Safari/537.36'
    }
    HTTP_SESSION_PROXIES = {
        'http': 'http://10.154.11.143:8888',
        'https': 'http://10.154.11.143:8888'
    }
    WAFW00F_PROXY = 'http://10.154.11.143:8888'
    NGINX_SAFE_VERSION = '1.16.1'


class ProductionConfig(Config):
    pass


class DevelopmentConfig(Config):
    pass


class TestConfig(Config):
    pass


def config():
    env = os.getenv('ENV', '')

    if env == PROD:
        return ProductionConfig

    if env == TEST:
        return TestConfig

    return DevelopmentConfig
