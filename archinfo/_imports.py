"""
This module exists to consolidate optional depdencies in one place.
"""

try:
    import capstone as _capstone
except ImportError:
    _capstone = None

try:
    import keystone as _keystone
except ImportError:
    _keystone = None

try:
    import pyvex as _pyvex
except ImportError:
    _pyvex = None

try:
    import unicorn as _unicorn
except ImportError:
    _unicorn = None


__all__ = ['_capstone', '_keystone', '_pyvex', '_unicorn']
