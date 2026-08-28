# pylint:disable=missing-class-docstring,no-self-use
import pickle
import unittest

from archinfo import (
    ArchARM,
    ArchARMCortexM,
    ArchARMEL,
    ArchARMHF,
    ArchError,
    ArchPcode,
    ArchS390X,
    Endness,
    arch_from_id,
)
from archinfo.arch_arm import is_arm_arch

try:
    import pypcode
except ImportError:
    pypcode = None


@unittest.skipUnless(pypcode is not None, "pypcode not installed")
class TestArchPcode(unittest.TestCase):
    def test_arch_68000(self):
        arch = ArchPcode("68000:BE:32:default")
        assert arch.instruction_endness == Endness.BE
        assert arch.bits == 32

    def test_arch_without_program_counter(self):
        """Dalvik and the DATA languages declare no program counter, so archinfo reports none."""
        for lang_id in ("Dalvik:LE:32:DEX_Nougat", "DATA:LE:64:default"):
            arch = ArchPcode(lang_id)
            assert arch.ip_offset is None
            assert "ip" not in arch.registers
            assert "pc" not in arch.registers

    def test_arch_with_program_counter(self):
        """A language that names its program counter keeps naming it, under pc and ip both."""
        arch = ArchPcode("x86:LE:64:default")
        assert arch.registers["ip"] == arch.registers["rip"]
        assert arch.registers["pc"] == arch.registers["rip"]
        assert arch.ip_offset == arch.registers["rip"][0]

    def test_arch_with_narrow_stack_pointer(self):
        """The 8051's stack pointer is one byte wide, narrower than its 16-bit address space."""
        arch = ArchPcode("8051:BE:16:default")
        assert arch.registers["sp"][1] == 1
        assert arch.initial_sp == 0x7F

        # architectures with a stack pointer at least 16 bits wide keep the initial stack pointer they always had
        assert ArchPcode("z80:LE:16:default").initial_sp == 0x7FFF
        assert ArchPcode("68000:BE:32:default").initial_sp == 0x7FFFFFFF
        assert ArchPcode("x86:LE:64:default").initial_sp == 0x7FFFFFFFFFFFFFFF

    def test_arm_language_is_not_an_archinfo_arm_arch(self):
        # CFG recovery in angr guards its ARM/Thumb handling with is_arm_arch and then reads Thumb
        # prologues, the itstate register and the ARM CFG option table, none of which a p-code ARM
        # language has. See https://github.com/angr/angr/issues/4779.
        for language in ("ARM:LE:32:v7", "ARM:BE:32:v7", "ARM:LE:32:Cortex", "ARM:LE:32:v8"):
            assert not is_arm_arch(ArchPcode(language))
        for arch in (ArchARM(), ArchARMEL(), ArchARMHF(), ArchARMCortexM()):
            assert is_arm_arch(arch)

    def test_arch_bad_langid(self):
        with self.assertRaises(ArchError):
            ArchPcode("invalid")

    def test_pickle(self):
        arch = ArchPcode("68000:BE:32:default")
        pickle.dumps(arch)

    def test_pcode_method_from_regular_arch(self):
        """Test that regular architectures can return ArchPcode instances via pcode() method"""
        # Test AMD64
        amd64 = arch_from_id("amd64")
        pcode_arch = amd64.pcode_arch()
        assert isinstance(pcode_arch, ArchPcode)
        assert pcode_arch.pcode_id == "x86:LE:64:default"
        assert pcode_arch.bits == 64

        # Test X86
        x86 = arch_from_id("x86")
        pcode_arch = x86.pcode_arch()
        assert isinstance(pcode_arch, ArchPcode)
        assert pcode_arch.pcode_id == "x86:LE:32:default"
        assert pcode_arch.bits == 32

        # Test ARM LE
        arm_le = arch_from_id("arm", Endness.LE)
        pcode_arch = arm_le.pcode_arch()
        assert isinstance(pcode_arch, ArchPcode)
        assert pcode_arch.pcode_id == "ARM:LE:32:v7"
        assert pcode_arch.bits == 32

        # Test ARM BE
        arm_be = arch_from_id("arm", Endness.BE)
        pcode_arch = arm_be.pcode_arch()
        assert isinstance(pcode_arch, ArchPcode)
        assert pcode_arch.pcode_id == "ARM:BE:32:v7"
        assert pcode_arch.bits == 32

        # Test MIPS32 LE
        mips_le = arch_from_id("mips32", Endness.LE)
        pcode_arch = mips_le.pcode_arch()
        assert isinstance(pcode_arch, ArchPcode)
        assert pcode_arch.pcode_id == "MIPS:LE:32:default"
        assert pcode_arch.bits == 32

        # Test MIPS32 BE
        mips_be = arch_from_id("mips32", Endness.BE)
        pcode_arch = mips_be.pcode_arch()
        assert isinstance(pcode_arch, ArchPcode)
        assert pcode_arch.pcode_id == "MIPS:BE:32:default"
        assert pcode_arch.bits == 32

        # Test AARCH64 LE
        aarch64_le = arch_from_id("aarch64", Endness.LE)
        pcode_arch = aarch64_le.pcode_arch()
        assert isinstance(pcode_arch, ArchPcode)
        assert pcode_arch.pcode_id == "AARCH64:LE:64:v8A"
        assert pcode_arch.bits == 64

        # Test AARCH64 BE
        aarch64_be = arch_from_id("aarch64", Endness.BE)
        pcode_arch = aarch64_be.pcode_arch()
        assert isinstance(pcode_arch, ArchPcode)
        assert pcode_arch.pcode_id == "AARCH64:BE:64:v8A"
        assert pcode_arch.bits == 64

        # Test PPC64 LE
        ppc64_le = arch_from_id("ppc64", Endness.LE)
        pcode_arch = ppc64_le.pcode_arch()
        assert isinstance(pcode_arch, ArchPcode)
        assert pcode_arch.pcode_id == "PowerPC:LE:64:default"
        assert pcode_arch.bits == 64

        # Test PPC64 BE
        ppc64_be = arch_from_id("ppc64", Endness.BE)
        pcode_arch = ppc64_be.pcode_arch()
        assert isinstance(pcode_arch, ArchPcode)
        assert pcode_arch.pcode_id == "PowerPC:BE:64:default"
        assert pcode_arch.bits == 64

        # Test RISCV64
        riscv64 = arch_from_id("riscv64")
        pcode_arch = riscv64.pcode_arch()
        assert isinstance(pcode_arch, ArchPcode)
        assert pcode_arch.pcode_id == "RISCV:LE:64:default"
        assert pcode_arch.bits == 64

    def test_pcode_method_from_archpcode(self):
        """Test that ArchPcode.pcode() returns itself"""
        pcode_arch = ArchPcode("x86:LE:64:default")
        result = pcode_arch.pcode_arch()
        assert result is pcode_arch
        assert isinstance(result, ArchPcode)

    def test_pcode_method_arch_without_pcode(self):
        """Test that architectures without pcode support raise ArchError"""
        s390x = ArchS390X()
        assert s390x.pcode_id is None
        with self.assertRaises(ArchError) as cm:
            s390x.pcode_arch()
        assert "does not have a pcode_arch defined" in str(cm.exception)


if __name__ == "__main__":
    unittest.main()
