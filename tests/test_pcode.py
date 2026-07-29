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
    def test_x86_real_mode_abi_metadata(self):
        language = pypcode.ArchLanguage.from_id("x86:LE:16:Real Mode")
        assert language is not None
        cspec = language.cspecs[("default", "default")]
        data_organization = cspec.find("data_organization")
        stack_pointer = cspec.find("stackpointer")
        default_output = cspec.find("./default_proto/prototype/output/pentry/register")
        assert data_organization is not None
        assert stack_pointer is not None
        assert default_output is not None
        pointer_size_element = data_organization.find("pointer_size")
        assert pointer_size_element is not None

        arch = ArchPcode(language)
        pointer_size = int(pointer_size_element.attrib["value"])
        stack_pointer_name = stack_pointer.attrib["register"]
        return_register_name = default_output.attrib["name"]

        assert arch.bits == 16
        assert arch.bytes == pointer_size == 2
        assert stack_pointer_name == "SP"
        assert arch.sp_offset == arch.registers[stack_pointer_name.lower()][0]
        assert arch.registers[stack_pointer_name.lower()][1] == pointer_size
        assert return_register_name == "AX"
        assert arch.ret_offset == arch.registers[return_register_name.lower()][0]
        assert arch.registers[return_register_name.lower()][1] == 2

    def test_c_data_model_from_compiler_spec(self):
        type_size_tags = {
            "short": "short_size",
            "int": "integer_size",
            "long": "long_size",
            "long long": "long_long_size",
        }
        cases = (
            (
                "x86:LE:16:Real Mode",
                ("default", "default"),
                {"short": 16, "int": 16, "long": 32, "long long": 32},
            ),
            (
                "avr8:LE:16:default",
                ("gcc", "gcc"),
                {"short": 16, "int": 16, "long": 32, "long long": 64},
            ),
            (
                "x86:LE:64:default",
                ("gcc", "gcc"),
                {"short": 16, "int": 32, "long": 64, "long long": 64},
            ),
        )

        for language_id, compiler, expected_sizes in cases:
            with self.subTest(language_id):
                language = pypcode.ArchLanguage.from_id(language_id)
                assert language is not None
                data_organization = language.cspecs[compiler].find("data_organization")
                assert data_organization is not None

                spec_sizes = {
                    c_type: int(data_organization.find(tag).attrib["value"]) * 8
                    for c_type, tag in type_size_tags.items()
                }
                pointer_size = data_organization.find("pointer_size")
                assert pointer_size is not None

                arch = ArchPcode(language)
                assert spec_sizes == expected_sizes
                assert arch.sizeof == expected_sizes
                assert int(pointer_size.attrib["value"]) * arch.byte_width == arch.bits

    def test_arch_68000(self):
        arch = ArchPcode("68000:BE:32:default")
        assert arch.instruction_endness == Endness.BE
        assert arch.bits == 32

    def test_arch_bad_langid(self):
        with self.assertRaises(ArchError):
            ArchPcode("invalid")

    def test_pickle(self):
        arch = ArchPcode("68000:BE:32:default")
        assert pickle.loads(pickle.dumps(arch)).disasm(b"\x4e\x71") == "0x0:\tnop "

        arch = ArchPcode("ARM:LE:32:v7")
        assert pickle.loads(pickle.dumps(arch)).disasm(b"\x00\xbf", thumb=True) == "0x0:\tnop "

    def test_disasm_without_thumb_mode(self):
        arch = ArchPcode("x86:LE:16:Real Mode")
        assert arch.disasm(b"") == ""
        with self.assertRaisesRegex(TypeError, "bytestring must be bytes"):
            arch.disasm(None)
        with self.assertRaisesRegex(TypeError, "bytestring must be bytes"):
            arch.disasm(bytearray())
        assert arch.disasm(b"\x90", addr=0x100) == "0x100:\tNOP "
        with self.assertLogs("archinfo.arch_pcode", level="WARNING") as logs:
            assert arch.disasm(b"\x90", addr=0x100, thumb=True) == "0x100:\tNOP "
        assert "without a TMode context variable" in logs.output[0]

        arch = ArchPcode("ARM:LE:32:v4")
        assert arch.disasm(b"\x00\x00\xa0\xe1", addr=0x100) == "0x100:\tmov r0,r0"

    def test_disasm_thumb_mode(self):
        arch = ArchPcode("ARM:LE:32:v7")
        assert arch.disasm(b"\x00\xbf", addr=0x100, thumb=True) == "0x100:\tnop "

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
