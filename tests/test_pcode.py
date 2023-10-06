# pylint:disable=missing-class-docstring,no-self-use
import pickle
import unittest

try:
    import pypcode
except ImportError:
    pypcode = None

from archinfo import ArchError, ArchPcode
from archinfo.arch import Endness


@unittest.skipUnless(pypcode is not None, "pypcode not installed")
class TestArchPcode(unittest.TestCase):
    def test_arch_68000(self):
        arch = ArchPcode("68000:BE:32:default")
        assert arch.instruction_endness == Endness.BE
        assert arch.bits == 32

    def test_arch_bad_langid(self):
        with self.assertRaises(ArchError):
            ArchPcode("invalid")

    def test_pickle(self):
        arch = ArchPcode("68000:BE:32:default")
        pickle.dumps(arch)


if __name__ == "__main__":
    unittest.main()
