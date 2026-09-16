# pylint:disable=missing-class-docstring,no-self-use
import struct
import unittest

from archinfo import ArchAMD64


class TestStructFmt(unittest.TestCase):
    def test_sizes_struct_can_express(self):
        arch = ArchAMD64()
        for size in (1, 2, 4, 8):
            for signed in (False, True):
                assert struct.calcsize(arch.struct_fmt(size=size, signed=signed)) == size

    def test_sizes_struct_cannot_express(self):
        arch = ArchAMD64()
        for size in (0, 3, 5, 6, 7, 16):
            with self.assertRaises(ValueError):
                arch.struct_fmt(size=size)


if __name__ == "__main__":
    unittest.main()
