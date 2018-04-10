import logging


fmt = "[%(levelname)s %(asctime)-15s] %(message)s"
timefmt = "%d %b %Y %H:%M:%S"
logger = logging.getLogger(__name__)
sh = logging.StreamHandler()
formatter = logging.Formatter(fmt, timefmt)
sh.setFormatter(formatter)
logger.addHandler(sh)


def name2level(level):
    return logging.__dict__.get(level.upper())


__all__ = [
    'logger',
    'name2level'
]
