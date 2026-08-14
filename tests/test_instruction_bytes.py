import unittest

from archinfo import (
    ArchAArch64,
    ArchAMD64,
    ArchARM,
    ArchMIPS32,
    ArchMIPS64,
    ArchPPC32,
    ArchPPC64,
    ArchRISCV64,
    ArchS390X,
    ArchX86,
)
from archinfo.arch import Endness, reverse_ends

# The encoding each architecture holds in memory, as a disassembler reads it.
EXPECTED = [
    # (class, endness, nop_instruction, ret_instruction)
    (ArchX86, Endness.LE, b"\x90", b"\xc3"),  # nop / ret
    (ArchAMD64, Endness.LE, b"\x90", b"\xc3"),  # nop / ret
    (ArchARM, Endness.LE, b"\x00\x00\x00\x00", b"\x1e\xff\x2f\xe1"),  # andeq r0, r0, r0 / bx lr
    (ArchARM, Endness.BE, b"\x00\x00\x00\x00", b"\xe1\x2f\xff\x1e"),
    (ArchPPC32, Endness.LE, b"\x00\x00\x00\x60", b"\x20\x00\x80\x4e"),  # nop / blr
    (ArchPPC32, Endness.BE, b"\x60\x00\x00\x00", b"\x4e\x80\x00\x20"),
    (ArchPPC64, Endness.LE, b"\x00\x00\x00\x60", b"\x20\x00\x80\x4e"),
    (ArchPPC64, Endness.BE, b"\x60\x00\x00\x00", b"\x4e\x80\x00\x20"),
    # jr $ra followed by its delay slot, or $at, $at, $zero
    (ArchMIPS32, Endness.LE, b"\x00\x00\x00\x00", b"\x08\x00\xe0\x03\x25\x08\x20\x00"),
    (ArchMIPS32, Endness.BE, b"\x00\x00\x00\x00", b"\x03\xe0\x00\x08\x00\x20\x08\x25"),
    (ArchMIPS64, Endness.LE, b"\x00\x00\x00\x00", b"\x08\x00\xe0\x03\x25\x08\x20\x00"),
    (ArchMIPS64, Endness.BE, b"\x00\x00\x00\x00", b"\x03\xe0\x00\x08\x00\x20\x08\x25"),
    # AArch64 and RISC-V keep little-endian instructions whatever the endness of data
    (ArchAArch64, Endness.LE, b"\x1f\x20\x03\xd5", b"\xc0\x03\x5f\xd6"),  # nop / ret
    (ArchAArch64, Endness.BE, b"\x1f\x20\x03\xd5", b"\xc0\x03\x5f\xd6"),
    (ArchRISCV64, Endness.LE, b"\x01\x00", b"\x82\x80"),  # c.nop / c.jr ra
    (ArchRISCV64, Endness.BE, b"\x01\x00", b"\x82\x80"),
    (ArchS390X, Endness.BE, b"\x07\x07", b"\x07\xfe"),  # nopr %r7 / br %r14
]


class TestInstructionBytes(unittest.TestCase):
    """Check that every architecture reports the encoding a disassembler reads out of memory."""

    def test_nop_and_ret_encodings(self):
        for cls, endness, nop, ret in EXPECTED:
            with self.subTest(arch=cls.__name__, endness=endness):
                arch = cls(endness)
                assert arch.nop_instruction == nop
                assert arch.ret_instruction == ret

    def test_instruction_length_is_preserved(self):
        for cls, endness, _, _ in EXPECTED:
            with self.subTest(arch=cls.__name__, endness=endness):
                arch = cls(endness)
                assert len(arch.nop_instruction) == len(cls.nop_instruction)
                assert len(arch.ret_instruction) == len(cls.ret_instruction)

    def test_reverse_ends_swaps_whole_words(self):
        self.assertEqual(reverse_ends(b""), b"")
        self.assertEqual(reverse_ends(b"\x01\x02\x03\x04"), b"\x04\x03\x02\x01")
        self.assertEqual(reverse_ends(b"\x01\x02\x03\x04\x05\x06\x07\x08"), b"\x04\x03\x02\x01\x08\x07\x06\x05")

    def test_reverse_ends_does_not_pad_a_short_word(self):
        self.assertEqual(reverse_ends(b"\x01\x02"), b"\x02\x01")
        self.assertEqual(reverse_ends(b"\x01\x02\x03\x04\x05\x06"), b"\x04\x03\x02\x01\x06\x05")


if __name__ == "__main__":
    unittest.main()
