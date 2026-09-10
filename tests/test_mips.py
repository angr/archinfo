# pylint:disable=no-self-use
from __future__ import annotations

import unittest

import archinfo
from archinfo import ArchMIPS32, ArchMIPS64, ArchMIPSN32, all_arches, arch_from_id
from archinfo.arch import Arch, Endness

try:
    import pyvex
except ImportError:
    pyvex = None

try:
    import pypcode
except ImportError:
    pypcode = None

# archinfo declares no dependencies, so a bare install has no pyvex and Arch.__init__ leaves the
# register file empty. Anything that reads arch.registers has to say so rather than KeyError.
requires_pyvex = unittest.skipUnless(pyvex is not None, "the register file needs pyvex")
requires_pypcode = unittest.skipUnless(pypcode is not None, "resolving a language id needs pypcode")


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

    def test_pcode_id_names_the_32_bit_address_language(self):
        assert ArchMIPSN32(Endness.BE).pcode_id == "MIPS:BE:64:64-32addr"
        assert ArchMIPSN32(Endness.LE).pcode_id == "MIPS:LE:64:64-32addr"
        for endness in (Endness.BE, Endness.LE):
            assert ArchMIPSN32(endness).pcode_id != ArchMIPS64(endness).pcode_id

    @requires_pypcode
    def test_pcode_id_resolves(self):
        for endness in (Endness.BE, Endness.LE):
            arch = ArchMIPSN32(endness)
            assert arch.pcode_arch().pcode_id == arch.pcode_id

    def test_c_types(self):
        arch = ArchMIPSN32(Endness.BE)
        assert arch.sizeof["long"] == 32
        assert arch.sizeof["long long"] == 64


class TestArchLookupByName(unittest.TestCase):
    """
    arch_from_id has to hand back the architecture whose name it was given.
    """

    def test_mipsn32_is_registered(self):
        assert ArchMIPSN32 in {type(arch) for arch in all_arches}

    def test_mipsn32_resolves_from_its_own_name(self):
        # A caller that round-trips an architecture through its name -- angr's SimLibrary does
        # exactly this to canonicalise the keys of its default calling-convention table -- used to
        # get ArchMIPS32 back, which has neither the same register file nor the same instruction
        # width. The n32 conventions then landed on the MIPS32 key and overwrote it.
        assert type(arch_from_id(ArchMIPSN32.name)) is ArchMIPSN32
        assert arch_from_id(ArchMIPSN32.name).name == ArchMIPSN32.name

    def test_every_named_arch_resolves_from_its_own_name(self):
        # The control for the case above: every other architecture archinfo exports already
        # round-trips, so a failure here is about the one that does not rather than about
        # arch_from_id being unable to resolve anything.
        for attr in archinfo.__all__:
            cls = getattr(archinfo, attr)
            if not isinstance(cls, type) or not issubclass(cls, Arch):
                continue
            name = getattr(cls, "name", None)
            if name is None:  # Arch and ArchPcode carry no fixed name
                continue
            assert arch_from_id(name).name == name, attr

    def test_o32_identifiers_are_untouched(self):
        # ArchMIPS32's catch-all now declines the n32 spellings. It still has to claim every
        # other MIPS identifier it claimed before, in the endness it claimed it in.
        for ident in ("mips", "mips32", "MIPS32"):
            assert type(arch_from_id(ident)) is ArchMIPS32, ident
        for ident in ("mipsel", "mipsle"):
            assert type(arch_from_id(ident)) is ArchMIPS32, ident
            assert arch_from_id(ident).memory_endness == Endness.LE, ident
        for ident in ("mips64", "MIPS64"):
            assert type(arch_from_id(ident)) is ArchMIPS64, ident
        assert arch_from_id("mips64el").memory_endness == Endness.LE

    def test_n32_identifiers_carry_their_endness(self):
        assert arch_from_id("mipsn32").memory_endness == Endness.BE
        for ident in ("mipsn32el", "mipsn32le"):
            assert type(arch_from_id(ident)) is ArchMIPSN32, ident
            assert arch_from_id(ident).memory_endness == Endness.LE, ident


if __name__ == "__main__":
    unittest.main()
