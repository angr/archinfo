# pylint:disable=missing-class-docstring,no-self-use
import pickle
import unittest

from archinfo import ArchError, ArchPcode, ArchS390X, Endness, arch_from_id

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
