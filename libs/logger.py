import logging

DA_log = logging.getLogger("common_logger")
streamHanlder = logging.StreamHandler()
dex_analysis_format = logging.Formatter("%(asctime)s [%(filename)s:%(lineno)s] [%(levelname)s] - %(message)s")
streamHanlder.setFormatter(dex_analysis_format)
DA_log.addHandler(streamHanlder)
DA_log.setLevel(logging.DEBUG)

def set_DA_LoggerLevel(level):
    if level == "CRITICAL":
        DA_log.setLevel(logging.CRITICAL)
    if level == "ERROR":
        DA_log.setLevel(logging.ERROR)
    if level == "WARNING":
        DA_log.setLevel(logging.WARNING)
    if level == "INFO":
        DA_log.setLevel(logging.INFO)
    if level == "DEBUG":
        DA_log.setLevel(logging.DEBUG)

def get_DA_logger():
    return DA_log