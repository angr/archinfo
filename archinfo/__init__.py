# pylint: disable=wildcard-import
from .arch import *

import os as _os

defines = {}

filepath = _os.path.join(_os.path.dirname(_os.path.realpath(__file__)), 'defines.dat')
for line in open(filepath):
    line_items = line.split()
    if len(line_items) == 0:
        continue
    defines[line_items[0]] = int(line_items[1], 0)

