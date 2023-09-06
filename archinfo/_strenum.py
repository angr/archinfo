"""
This file is copied from here: https://github.com/clbarnes/backports.strenum/blob/main/backports/strenum/strenum.py
It is licensed under the Python Software Foundation License Version 2.

This file should be replaced with backports.strenum once its packaging issues
are resolved. See here: https://github.com/clbarnes/backports.strenum/issues/9
Alternatively, if archifo is sooner updated to Python 3.11, this file can be
removed and replaced with the standard library version.
"""
import sys
from enum import Enum
from typing import Any, List, Type, TypeVar

if sys.version_info <= (3, 11):
    _S = TypeVar("_S", bound="StrEnum")

    class StrEnum(str, Enum):
        """
        Enum where members are also (and must be) strings
        """

        def __new__(cls: Type[_S], *values: str) -> _S:
            if len(values) > 3:
                raise TypeError(f"too many arguments for str(): {values!r}")
            if len(values) == 1:
                # it must be a string
                if not isinstance(values[0], str):
                    raise TypeError(f"{values[0]!r} is not a string")
            if len(values) >= 2:
                # check that encoding argument is a string
                if not isinstance(values[1], str):
                    raise TypeError(f"encoding must be a string, not {values[1]!r}")
            if len(values) == 3:
                # check that errors argument is a string
                if not isinstance(values[2], str):
                    raise TypeError("errors must be a string, not %r" % (values[2]))
            value = str(*values)
            member = str.__new__(cls, value)
            member._value_ = value
            return member

        __str__ = str.__str__

        @staticmethod
        def _generate_next_value_(name: str, start: int, count: int, last_values: List[Any]) -> str:
            """
            Return the lower-cased version of the member name.
            """
            return name.lower()

else:
    from enum import StrEnum
