# pylint:disable=no-self-use
from __future__ import annotations

import inspect
import unittest

from archinfo import ArchPPC32, ArchPPC64, arch_from_id
from archinfo.arch import Endness

# The unqualified names are the big-endian ports. The little-endian spellings carry an el or le
# suffix -- ppc64el is the Debian architecture, powerpc64le the GNU triplet, ppc_le the name cle's
# binja backend uses -- so a suffix is what arch_from_id has to go on.
BIG_ENDIAN = [
    ("ppc", ArchPPC32),
    ("PowerPC", ArchPPC32),
    ("powerpc", ArchPPC32),
    ("ppc32", ArchPPC32),
    ("ppcbe", ArchPPC32),
    ("powerpcbe", ArchPPC32),
    ("powerpc-linux-gnu", ArchPPC32),
    ("powerpc-eabi", ArchPPC32),
    ("powerpcspe", ArchPPC32),
    # elf ends in el, which is why the little-endian pattern is not the mirror of the big-endian
    # one. These are bare-metal big-endian targets and the suffix match must not reach them.
    ("powerpc-elf", ArchPPC32),
    ("ppc-elf", ArchPPC32),
    ("powerpc-none-elf", ArchPPC32),
    ("powerpc-elfv2", ArchPPC32),
    ("ppc64-elf", ArchPPC64),
    ("ppc64", ArchPPC64),
    ("powerpc64", ArchPPC64),
    ("ppc64be", ArchPPC64),
    ("powerpc64-linux-gnu", ArchPPC64),
]

LITTLE_ENDIAN = [
    ("ppcle", ArchPPC32),
    ("ppcel", ArchPPC32),
    ("powerpcle", ArchPPC32),
    ("ppc64le", ArchPPC64),
    ("ppc64el", ArchPPC64),
    ("powerpc64le", ArchPPC64),
    ("ppc64le-linux-gnu", ArchPPC64),
    ("ppc64el-linux-gnu", ArchPPC64),
    ("powerpc64le-linux-gnu", ArchPPC64),
    # A separator may sit between the name and the suffix. ppc_le is the identifier cle's binja
    # backend maps to a little-endian ArchPPC32.
    ("ppc_le", ArchPPC32),
    ("ppc-le", ArchPPC32),
    ("powerpc-le", ArchPPC32),
    ("ppc64_le", ArchPPC64),
    ("ppc64_el", ArchPPC64),
]


class TestPPCEndnessIdentifiers(unittest.TestCase):
    """
    PowerPC is bi-endian and archinfo ships both, so which one an identifier means has to come
    from the identifier. When the caller passes no endness, arch_from_id takes it from the
    registration that matched, falling back to default_endness for a registration made with
    Endness.ANY.
    """

    def test_unqualified_identifiers_are_big_endian(self):
        for ident, cls in BIG_ENDIAN:
            arch = arch_from_id(ident)
            assert type(arch) is cls, ident
            assert arch.memory_endness == Endness.BE, ident

    def test_el_and_le_identifiers_are_little_endian(self):
        for ident, cls in LITTLE_ENDIAN:
            arch = arch_from_id(ident)
            assert type(arch) is cls, ident
            assert arch.memory_endness == Endness.LE, ident

    def test_an_explicit_endness_still_wins(self):
        for ident, _ in BIG_ENDIAN + LITTLE_ENDIAN:
            assert arch_from_id(ident, Endness.LE).memory_endness == Endness.LE, ident
            assert arch_from_id(ident, Endness.BE).memory_endness == Endness.BE, ident

    def test_constructing_without_an_endness_agrees_with_default_endness(self):
        # arch_from_id reads default_endness while a direct construction reads the parameter
        # default, so the two have to name the same endness or the same architecture arrives
        # little-endian down one path and big-endian down the other.
        for cls in (ArchPPC32, ArchPPC64):
            parameter = inspect.signature(cls.__init__).parameters["endness"]
            assert parameter.default == cls.default_endness, cls.__name__
            assert cls().memory_endness == Endness.BE, cls.__name__


if __name__ == "__main__":
    unittest.main()
