import logging
import colorlog
import os

os.makedirs("logs/reports", exist_ok=True)

handler = colorlog.StreamHandler()
handler.setFormatter(colorlog.ColoredFormatter(
    "%(log_color)s%(asctime)s [%(levelname)s] %(message)s",
    log_colors={
        "DEBUG": "cyan",
        "INFO": "green",
        "WARNING": "yellow",
        "ERROR": "red",
        "CRITICAL": "bold_red",
    }
))

file_handler = logging.FileHandler("logs/threats.log")
file_handler.setFormatter(logging.Formatter(
    "%(asctime)s [%(levelname)s] %(message)s"
))

logger = logging.getLogger("cybersec")
logger.setLevel(logging.DEBUG)
logger.addHandler(handler)
logger.addHandler(file_handler)