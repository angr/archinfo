# pylint:disable=no-self-use
from __future__ import annotations

import unittest

from archinfo import ArchMIPS64, ArchMIPSN32
from archinfo.arch import Endness


class TestArchMIPSN32(unittest.TestCase):
    """
    n32 and O64 are 64-bit MIPS instruction streams with 32-bit pointers, so ArchMIPSN32 has to
    disagree with ArchMIPS64 about the word size and agree with it about everything else.
    """

    def test_word_size_is_32_bit(self):
        arch = ArchMIPSN32(Endness.BE)
        assert arch.bits == 32
        assert arch.bytes == 4
        # This is what decides how wide a word CLE reads out of and writes back into a
        # relocation slot; n32 relocation entries, GOT slots and pointers are all 4 bytes.
        assert arch.struct_fmt() == ">I"

    def test_instruction_set_is_64_bit(self):
        arch = ArchMIPSN32(Endness.BE)
        assert arch.vex_arch == "VexArchMIPS64"
        assert arch.name != ArchMIPS64.name
        # The hardware registers stay 64-bit even though a pointer does not.
        assert arch.registers["sp"][1] == 8
        assert arch.registers["ra"][1] == 8
        assert arch.registers["pc"][1] == 8

    def test_endness(self):
        assert ArchMIPSN32(Endness.BE).memory_endness == Endness.BE
        assert ArchMIPSN32(Endness.LE).memory_endness == Endness.LE
        assert ArchMIPSN32(Endness.LE).struct_fmt() == "<I"

    def test_c_types(self):
        arch = ArchMIPSN32(Endness.BE)
        assert arch.sizeof["long"] == 32
        assert arch.sizeof["long long"] == 64


if __name__ == "__main__":
    unittest.main()
