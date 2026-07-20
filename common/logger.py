import logging
import sys
from config import DATA_DIR

def get_logger(name: str = "soc_assistant") -> logging.Logger:
    """Return a configured logger for telemetry."""
    logger = logging.getLogger(name)
    # Prevent adding handlers multiple times if get_logger is called repeatedly
    if logger.hasHandlers():
        return logger

    logger.setLevel(logging.INFO)

    # Console handler: keeps terminal output clean, similar to standard print
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    formatter = logging.Formatter('%(message)s')
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    # File handler: full telemetry with timestamps and levels
    log_file = DATA_DIR / "soc_assistant.log"
    # Ensure data dir exists
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    fh = logging.FileHandler(log_file, encoding='utf-8')
    fh.setLevel(logging.INFO)
    file_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    fh.setFormatter(file_formatter)
    logger.addHandler(fh)

    return logger
