# pylint:disable=no-self-use
from __future__ import annotations

import unittest

from archinfo import ArchMIPS64, ArchMIPSN32
from archinfo.arch import Endness

try:
    import pyvex
except ImportError:
    pyvex = None

# archinfo declares no dependencies, so a bare install has no pyvex and Arch.__init__ leaves the
# register file empty. Anything that reads arch.registers has to say so rather than KeyError.
requires_pyvex = unittest.skipUnless(pyvex is not None, "the register file needs pyvex")


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

    @requires_pyvex
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

    @requires_pyvex
    def test_argument_registers_stay_64_bit(self):
        # bits == 32 is the pointer width. Anything that slots an argument into one of these
        # registers has to take the width from the register file, not from bits: a consumer that
        # divides bits by eight describes a0 as four bytes and, on big-endian, then writes a 32-bit
        # argument into the sign-extension half that the callee never reads.
        for endness in (Endness.BE, Endness.LE):
            arch = ArchMIPSN32(endness)
            assert arch.bytes == 4
            for name in ["a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", "v0", "v1"]:
                assert arch.registers[name][1] == 8, name
                assert arch.registers[name] == ArchMIPS64(endness).registers[name], name

    def test_c_types(self):
        arch = ArchMIPSN32(Endness.BE)
        assert arch.sizeof["long"] == 32
        assert arch.sizeof["long long"] == 64


if __name__ == "__main__":
    unittest.main()
