import logging
from rikka.exceptions import ConfigError


fmt = "[%(levelname)s %(asctime)-15s] %(message)s"
timefmt = "%d %b %Y %H:%M:%S"
logger = logging.getLogger(__name__)
sh = logging.StreamHandler()
formatter = logging.Formatter(fmt, timefmt)
sh.setFormatter(formatter)
logger.addHandler(sh)


def name2level(level_name: str) -> int:
    """convert level name to logging level[int]"""
    level_name = level_name.upper()
    level = logging._nameToLevel.get(level_name)
    if level is None:
        raise ConfigError(
            "logging module doesn't support this level {}".format(level_name)
        )
    return level


__all__ = [
    'logger',
    'name2level'
]
