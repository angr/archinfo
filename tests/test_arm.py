# pylint:disable=no-self-use
import unittest

from archinfo import ArchARM, ArchARMEL, ArchARMHF
from archinfo.arch import Endness

try:
    import pyvex
except ImportError:
    pyvex = None

BX_LR = b"\x1e\xff\x2f\xe1"  # bx lr, as stored in a little-endian instruction stream
PUSH_LR = rb"\x04\xe0\x2d\xe5"  # push {lr}, likewise
PUSH_LR_REVERSED = rb"\xe5\x2d\xe0\x04"


needs_pyvex = unittest.skipUnless(pyvex is not None, "pyvex not installed")


def vex_endness(arch):
    # Only meaningful under needs_pyvex: without pyvex archinfo leaves vex_archinfo unset.
    archinfo = arch.vex_archinfo
    assert archinfo is not None
    return archinfo["endness"]


class TestArchArm(unittest.TestCase):
    """
    Test the three ARM instruction and data endianness combinations.
    """

    def test_little_endian(self):
        arch = ArchARM(Endness.LE)
        assert arch.memory_endness == Endness.LE
        assert arch.instruction_endness == Endness.LE
        assert arch.pcode_id == "ARM:LE:32:v7"
        assert arch.ret_instruction == BX_LR
        assert PUSH_LR in arch.function_prologs

    def test_be32(self):
        arch = ArchARM(Endness.BE)
        assert arch.memory_endness == Endness.BE
        assert arch.register_endness == Endness.BE
        assert arch.instruction_endness == Endness.BE
        assert arch.pcode_id == "ARM:BE:32:v7"
        assert arch.ret_instruction == BX_LR[::-1]
        assert PUSH_LR_REVERSED in arch.function_prologs

    @needs_pyvex
    def test_be32_lifts_instructions_big_endian(self):
        assert vex_endness(ArchARM(Endness.BE)) != vex_endness(ArchARM(Endness.LE))

    def test_be8_keeps_data_big_endian(self):
        arch = ArchARMHF(Endness.BE, instruction_endness=Endness.LE)
        assert arch.name == "ARMHF"
        assert arch.memory_endness == Endness.BE
        assert arch.register_endness == Endness.BE
        assert arch.instruction_endness == Endness.LE
        assert arch.pcode_id == "ARM:LEBE:32:v7LEInstruction"
        assert arch.fp_ret_offset == ArchARMHF(Endness.LE).fp_ret_offset

    def test_be8_keeps_instruction_encodings_little_endian(self):
        arch = ArchARMEL(Endness.BE, instruction_endness=Endness.LE)
        little = ArchARMEL(Endness.LE)
        assert arch.ret_instruction == BX_LR
        assert arch.nop_instruction == little.nop_instruction
        assert PUSH_LR in arch.function_prologs
        assert PUSH_LR_REVERSED not in arch.function_prologs
        assert arch.function_prologs == little.function_prologs
        assert arch.thumb_prologs == little.thumb_prologs
        assert arch.function_epilogs == little.function_epilogs
        assert arch.cs_mode == little.cs_mode
        assert arch.ks_mode == little.ks_mode

    @needs_pyvex
    def test_be8_lifts_instructions_little_endian(self):
        # VEX fetches instruction words through the guest endness, so a BE8 guest has to be
        # described to it as little-endian or nothing decodes.
        arch = ArchARMEL(Endness.BE, instruction_endness=Endness.LE)
        assert vex_endness(arch) == vex_endness(ArchARMEL(Endness.LE))
        assert vex_endness(arch) != vex_endness(ArchARMEL(Endness.BE))

    def test_be8_is_distinct_from_be32(self):
        be8 = ArchARMHF(Endness.BE, instruction_endness=Endness.LE)
        be32 = ArchARMHF(Endness.BE)
        assert be8 != be32
        assert len({be8, be32}) == 2


if __name__ == "__main__":
    unittest.main()
