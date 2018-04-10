import json
from collections import UserDict
# from sea.datatypes import ConstantsObject


class ConfigAttribute:
    """Makes an attribute forward to the config"""

    def __init__(self, name, get_converter=None):
        self.__name__ = name
        self.get_converter = get_converter

    def __get__(self, obj, tp=None):
        if obj is None:
            return self
        rv = obj.config[self.__name__]
        if self.get_converter is not None:
            rv = self.get_converter(rv)
        return rv

    def __set__(self, obj, value):
        obj.config[self.__name__] = value


class Config(UserDict):

    @classmethod
    def from_object(cls, obj):
        return cls(**obj.__dict__)

    def load_file(self, path):
        with open(path, 'r') as f:
            data = json.load(f)
            self.update(data)

    def __getattr__(self, attr):
        return self.data[attr]
