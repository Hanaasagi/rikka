import json
from collections import UserDict
from rikka.exceptions import ConfigMissing


from typing import Callable, List, Optional, Any


class ConfigAttribute:
    """Makes an attribute forward to the config"""

    def __init__(self, name: str,
                 get_converter: Optional[Callable] = None
                 # is there a better to express callable argument
                 ) -> None:
        self.__name__ = name
        self.get_converter = get_converter

    def __get__(self, obj: Any, tp: Optional[type] = None) -> Any:
        if obj is None:
            return self
        rv = obj.config[self.__name__]
        if self.get_converter is not None:
            rv = self.get_converter(rv)
        return rv

    def __set__(self, obj: Any, value: Any) -> None:
        obj.config[self.__name__] = value


class Config(UserDict):

    def from_object(self, obj: Any) -> None:
        self.merge(obj.__dict__)

    def load_file(self, path: str) -> None:
        with open(path, 'r') as f:
            data = json.load(f)
            self.update(data)

    # def merge(self, d: Dict) -> None:
        # for k, v in d.items():
            # self.data[k] = v

    def __getattr__(self, attr: str) -> Any:
        return self.data[attr]

    def validate(self, attrs: List[str]) -> None:
        for attr in attrs:
            if self.data.get(attr) is None:
                raise ConfigMissing(attr)

    merge = UserDict.update


__all__ = [
    'Config',
    'ConfigAttribute',
]
