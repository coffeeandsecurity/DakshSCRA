# Standard libraries
import logging
from functools import lru_cache


@lru_cache(maxsize=None)
def _get_base_logger():
    """
    Configure and return the base logger for the tool.

    Using lru_cache ensures the configuration only happens once even if multiple
    modules request a logger.
    """
    logger = logging.getLogger("dakshscra")

    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
        logger.addHandler(handler)

    logger.setLevel(logging.INFO)
    logger.propagate = False
    return logger


def get_logger(name=None):
    """
    Return a child logger with the shared configuration.

    Parameters:
        name (str): Optional child logger name. If omitted, the base logger is returned.
    """
    base = _get_base_logger()
    return base.getChild(name) if name else base
