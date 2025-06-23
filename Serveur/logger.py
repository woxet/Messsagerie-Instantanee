# logger.py
import os
import logging
from datetime import datetime

LOG_DIR = "./logs"
LOG_SYS = os.path.join(LOG_DIR, "sys.log")
# LOG_MESSAGES = os.path.join(LOG_DIR, "messages.log")


def ensure_log_dirs():
    os.makedirs(LOG_DIR, exist_ok=True)


def init_sys_logger():
    ensure_log_dirs()
    logger = logging.getLogger("sys")  # Logger nommé "sys"
    logger.setLevel(logging.INFO)

    if not logger.handlers:
        console_handler = logging.StreamHandler()
        file_handler = logging.FileHandler(LOG_SYS, mode="a", encoding="utf-8")

        formatter = logging.Formatter("[%(asctime)s] %(levelname)s - %(message)s")
        console_handler.setFormatter(formatter)
        file_handler.setFormatter(formatter)

        logger.addHandler(console_handler)
        logger.addHandler(file_handler)

    return logger
