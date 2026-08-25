# pylint:disable=no-self-use
from __future__ import annotations

import unittest

from archinfo import ArchARM, ArchARMHF
from archinfo.arch import Endness

BX_LR_LE = b"\x1e\xff\x2f\xe1"
PUSH_LR_LE = rb"\x04\xe0\x2d\xe5"
PUSH_LR_BE = rb"\xe5\x2d\xe0\x04"


class TestArchArm(unittest.TestCase):
    """
    Test the ARM architecture definitions, including BE8.
    """

    def test_le(self):
        arch = ArchARM(Endness.LE)
        assert arch.memory_endness == Endness.LE
        assert arch.instruction_endness == Endness.LE
        assert arch.pcode_id == "ARM:LE:32:v7"
        assert arch.ret_instruction == BX_LR_LE
        assert PUSH_LR_LE in arch.function_prologs

    def test_be32(self):
        arch = ArchARM(Endness.BE)
        assert arch.memory_endness == Endness.BE
        assert arch.register_endness == Endness.BE
        assert arch.instruction_endness == Endness.BE
        assert arch.pcode_id == "ARM:BE:32:v7"
        assert arch.ret_instruction == BX_LR_LE[::-1]
        assert PUSH_LR_BE in arch.function_prologs

    def test_be8(self):
        arch = ArchARMHF(Endness.BE, instruction_endness=Endness.LE)
        assert arch.name == "ARMHF"
        assert arch.memory_endness == Endness.BE
        assert arch.register_endness == Endness.BE
        assert arch.instruction_endness == Endness.LE
        assert arch.pcode_id == "ARM:LEBE:32:v7LEInstruction"
        assert arch.fp_ret_offset == ArchARMHF(Endness.LE).fp_ret_offset

    def test_be8_instruction_encodings_stay_little_endian(self):
        arch = ArchARMHF(Endness.BE, instruction_endness=Endness.LE)
        assert arch.ret_instruction == BX_LR_LE
        assert PUSH_LR_LE in arch.function_prologs
        assert PUSH_LR_BE not in arch.function_prologs
        assert arch.cs_mode == ArchARMHF(Endness.LE).cs_mode
        assert arch.ks_mode == ArchARMHF(Endness.LE).ks_mode
        assert arch.uc_mode == ArchARMHF(Endness.LE).uc_mode

    def test_be8_is_distinct_from_be32(self):
        be8 = ArchARMHF(Endness.BE, instruction_endness=Endness.LE)
        be32 = ArchARMHF(Endness.BE)
        assert be8 != be32
        assert len({be8, be32}) == 2


if __name__ == "__main__":
    unittest.main()
