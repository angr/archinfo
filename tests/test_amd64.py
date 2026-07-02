import unittest

from archinfo import ArchAMD64, ArchError
from archinfo.arch import Endness


class TestAmd64(unittest.TestCase):
    def test_arch_amd64(self):
        endness = Endness.LE
        assert ArchAMD64(endness)

    def test_arch_amd64_passes(self):
        with self.assertRaises(ArchError):
            endness = Endness.BE
            ArchAMD64(endness)

    def test_capstone_x86_syntax(self):
        inst_1 = ArchAMD64(endness=Endness.LE)
        assert inst_1.capstone_x86_syntax is None
        inst_1.capstone_x86_syntax = "intel"
        assert inst_1.capstone_x86_syntax == "intel"
        inst_1.capstone_x86_syntax = "at&t"
        assert inst_1.capstone_x86_syntax == "at&t"

    # Test raises one of expected exceptions to pass.
    def test_capstone_x86_syntax_fails_1(self):
        with self.assertRaises(ArchError):
            inst_1 = ArchAMD64(endness=Endness.LE)
            inst_1.capstone_x86_syntax = "at&"
            assert inst_1.capstone_x86_syntax

    def test_capstone_x86_syntax_fails_2(self):
        with self.assertRaises(ArchError):
            inst_1 = ArchAMD64(endness=Endness.LE)
            inst_1.capstone_x86_syntax = "int"
            assert inst_1.capstone_x86_syntax

    def test_assembler_support(self):
        inst_1 = ArchAMD64(endness=Endness.LE)
        assert inst_1.assembler_support
        assert inst_1.nyxstone_triple == "x86_64-linux-gnu"
        assert inst_1.asm("nop") == b"\x90"
