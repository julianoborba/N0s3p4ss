from pythonjsonlogger import jsonlogger
from logging import StreamHandler, getLogger
from structlog import getLogger as getStructLogger

handler = StreamHandler()
handler.setFormatter(jsonlogger.JsonFormatter())

logger = getLogger()
logger.addHandler(handler)


def get_logger():
    return getStructLogger('main')
