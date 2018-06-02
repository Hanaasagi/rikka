class ConfigMissing(Exception):
    """missing necessary config"""
    def __init__(self, msg: str) -> None:
        super().__init__("missing necessary config '{}'".format(msg))


class ConfigError(Exception):
    """Exception raised on config error"""


__all__ = [
    'ConfigMissing',
    'ConfigError'
]
