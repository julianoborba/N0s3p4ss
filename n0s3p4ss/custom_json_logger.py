from pythonjsonlogger import jsonlogger
from logging import StreamHandler, getLogger, INFO

json_handler = StreamHandler()
json_handler.setFormatter(jsonlogger.JsonFormatter())

custom_logger = getLogger('custom_logger')
custom_logger.addHandler(json_handler)
custom_logger.setLevel(INFO)

output_logger = getLogger('output_logger')
output_logger.addHandler(StreamHandler())
output_logger.setLevel(INFO)
