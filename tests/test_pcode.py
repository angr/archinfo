# pylint:disable=missing-class-docstring,no-self-use
import pickle
import unittest
from unittest.mock import patch

from archinfo import ArchError, ArchNotFound, ArchPcode, ArchS390X, Endness, arch_from_id

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

    def test_arch_bad_langid(self):
        with self.assertRaises(ArchError):
            ArchPcode("invalid")

    def test_arch_from_id_by_language_id(self):
        # A full sleigh language id names one language, and nothing registered can name it at all:
        # pypcode is the only definition of PA-RISC that archinfo has.
        arch = arch_from_id("pa-risc:BE:32:default")
        assert isinstance(arch, ArchPcode)
        assert arch.pcode_id == "pa-risc:BE:32:default"
        assert arch.bits == 32
        assert arch.memory_endness == Endness.BE

        # The id carries its own endness and width, so a hint that contradicts it does not apply.
        assert arch_from_id("Xtensa:BE:32:default", "le", 64).pcode_id == "Xtensa:BE:32:default"

    def test_arch_from_id_by_language_id_of_a_registered_arch(self):
        # arch_id_map resolves 74 of the 187 language ids pypcode ships to a VEX architecture, so an id
        # has to answer before that map or naming one of them silently returns that architecture.
        for language_id in ["ARM:LE:32:v7", "MIPS:BE:32:default", "PowerPC:BE:64:default", "x86:LE:16:Real Mode"]:
            arch = arch_from_id(language_id)
            assert isinstance(arch, ArchPcode)
            assert arch.pcode_id == language_id

    def test_arch_from_id_round_trips_every_language(self):
        # angr's database serializer stores an architecture as (name, memory_endness, bits) and
        # reloads it with arch_from_id, and ArchPcode.name is the language id.
        assert pypcode is not None
        for pcode_arch in pypcode.Arch.enumerate():
            for language in pcode_arch.languages:
                arch = ArchPcode(language)
                restored = arch_from_id(arch.name, arch.memory_endness, arch.bits)
                assert isinstance(restored, ArchPcode)
                assert restored.pcode_id == language.id

    def test_arch_from_id_prefers_registered_arches(self):
        # An identifier that is not a language id resolves exactly as it always did.
        for ident in ["x86", "amd64", "arm", "aarch64", "mips32", "mips64", "ppc32", "ppc64", "s390x", "riscv64"]:
            assert not isinstance(arch_from_id(ident), ArchPcode)

    def test_arch_from_id_without_a_language(self):
        # An identifier shaped like a language id that names no language is still not found.
        with self.assertRaises(ArchNotFound):
            arch_from_id("nosucharch:LE:32:default")
        # pypcode has no little-endian SPARC variant of this language.
        with self.assertRaises(ArchNotFound):
            arch_from_id("sparc:LE:32:default")
        # A machine name is not a language id, and is not searched for as one.
        with self.assertRaises(ArchNotFound):
            arch_from_id("EM_PARISC", "be", 32)

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


class TestArchFromIdWithoutPypcode(unittest.TestCase):
    def test_arch_from_id_without_pypcode(self):
        # archinfo installed without the pcode extra has no language to reach, so ArchPcode refuses to
        # construct and arch_from_id answers exactly as it did before language ids were accepted at all.
        with patch("archinfo.arch_pcode._has_pypcode", False):
            assert arch_from_id("x86").name == "X86"
            with self.assertRaises(ArchNotFound):
                arch_from_id("pa-risc:BE:32:default")


if __name__ == "__main__":
    unittest.main()
