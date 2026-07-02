import unittest
from unittest.mock import patch

from archinfo import (
    ArchAArch64,
    ArchAMD64,
    ArchError,
    ArchMIPS32,
    ArchMIPS64,
    ArchPPC32,
    ArchPPC64,
    ArchRISCV64,
    ArchS390X,
    ArchX86,
)
from archinfo.arch import Endness
from archinfo.arch_arm import ArchARM, ArchARMCortexM


class TestAssemblerSupport(unittest.TestCase):
    """assembler_support must reflect both triple definition AND backend availability."""

    def test_support_true_when_installed(self):
        arch = ArchAMD64(Endness.LE)
        assert arch.assembler_support is True
        assert arch.keystone_support is True
        assert arch.nyxstone_support is True

    def test_support_false_when_not_installed(self):
        with patch("archinfo.arch._Nyxstone", None):
            arch = ArchAMD64(Endness.LE)
            assert arch.assembler_support is False
            assert arch.keystone_support is False

    def test_asm_raises_when_not_installed(self):
        with patch("archinfo.arch._Nyxstone", None):
            arch = ArchAMD64(Endness.LE)
            with self.assertRaises(ArchError):
                arch.asm("ret")


class TestAssemblerDeprecatedAliases(unittest.TestCase):
    def test_keystone_property_warns(self):
        arch = ArchAMD64(Endness.LE)
        import warnings

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            _ = arch.keystone
            assert len(w) == 1
            assert issubclass(w[0].category, DeprecationWarning)
            assert "deprecated" in str(w[0].message).lower()


class TestAmd64Assembly(unittest.TestCase):
    def setUp(self):
        self.arch = ArchAMD64(Endness.LE)

    def test_mov_imm(self):
        assert self.arch.asm("mov rax, 0x41") == b"\x48\xc7\xc0\x41\x00\x00\x00"

    def test_add_reg_reg(self):
        assert self.arch.asm("add rax, rbx") == b"\x48\x01\xd8"

    def test_push_pop(self):
        assert self.arch.asm("push rax; pop rbx") == b"\x50\x5b"

    def test_syscall(self):
        assert self.arch.asm("syscall") == b"\x0f\x05"

    def test_lea(self):
        assert self.arch.asm("lea rax, [rbx + 8]") == b"\x48\x8d\x43\x08"

    def test_memory_operand(self):
        assert self.arch.asm("mov [rsp + 0x10], rax") == b"\x48\x89\x44\x24\x10"

    def test_ret(self):
        assert self.arch.asm("ret") == b"\xc3"

    def test_as_bytes_false(self):
        result = self.arch.asm("ret", as_bytes=False)
        assert isinstance(result, list)
        assert result == [0xC3]

    def test_bytes_input(self):
        assert self.arch.asm(b"ret") == b"\xc3"

    def test_invalid_instruction_raises(self):
        with self.assertRaises(ArchError):
            self.arch.asm("not_a_real_instruction")


class TestX86Assembly(unittest.TestCase):
    def setUp(self):
        self.arch = ArchX86(Endness.LE)

    def test_mov_imm(self):
        assert self.arch.asm("mov eax, 1") == b"\xb8\x01\x00\x00\x00"

    def test_add_reg_imm(self):
        assert self.arch.asm("add eax, 0xf") == b"\x83\xc0\x0f"

    def test_push_pop(self):
        assert self.arch.asm("push eax; pop ebx") == b"\x50\x5b"

    def test_int_80(self):
        assert self.arch.asm("int 0x80") == b"\xcd\x80"


class TestArmAssembly(unittest.TestCase):
    def test_le_mov(self):
        arch = ArchARM(Endness.LE)
        assert arch.asm("mov r0, #1") == b"\x01\x00\xa0\xe3"

    def test_le_add(self):
        arch = ArchARM(Endness.LE)
        assert arch.asm("add r1, r1, #0xf") == b"\x0f\x10\x81\xe2"

    def test_le_thumb_add(self):
        arch = ArchARM(Endness.LE)
        assert arch.asm("add.w r1, r1, #0xf", thumb=True) == b"\x01\xf1\x0f\x01"

    def test_le_thumb_mov(self):
        arch = ArchARM(Endness.LE)
        assert arch.asm("mov r0, #42", thumb=True) == b"\x4f\xf0\x2a\x00"

    def test_be_mov(self):
        arch = ArchARM(Endness.BE)
        assert arch.asm("mov r0, #1") == b"\xe3\xa0\x00\x01"


class TestArmCortexMAssembly(unittest.TestCase):
    def test_thumb_mov(self):
        arch = ArchARMCortexM()
        assert arch.asm("mov r0, #1", thumb=True) == b"\x4f\xf0\x01\x00"

    def test_thumb_add(self):
        arch = ArchARMCortexM()
        assert arch.asm("add r1, r1, #5", thumb=True) == b"\x01\xf1\x05\x01"


class TestAArch64Assembly(unittest.TestCase):
    def test_le_mov(self):
        arch = ArchAArch64(Endness.LE)
        assert arch.asm("mov x0, #1") == b"\x20\x00\x80\xd2"

    def test_le_add(self):
        arch = ArchAArch64(Endness.LE)
        assert arch.asm("add x0, x1, x2") == b"\x20\x00\x02\x8b"

    def test_le_ret(self):
        arch = ArchAArch64(Endness.LE)
        assert arch.asm("ret") == b"\xc0\x03\x5f\xd6"

    def test_be_mov(self):
        arch = ArchAArch64(Endness.BE)
        assert arch.asm("mov x0, #1") == b"\x20\x00\x80\xd2"


class TestMips32Assembly(unittest.TestCase):
    def test_le_addiu(self):
        arch = ArchMIPS32(Endness.LE)
        assert arch.asm("addiu $2, $2, 0xf") == b"\x0f\x00\x42\x24"

    def test_le_or(self):
        arch = ArchMIPS32(Endness.LE)
        assert arch.asm("or $2, $3, $4") == b"\x25\x10\x64\x00"

    def test_be_addiu(self):
        arch = ArchMIPS32(Endness.BE)
        assert arch.asm("addiu $2, $2, 0xf") == b"\x24\x42\x00\x0f"


class TestMips64Assembly(unittest.TestCase):
    def test_le_addiu(self):
        arch = ArchMIPS64(Endness.LE)
        assert arch.asm("addiu $2, $2, 0xf") == b"\x0f\x00\x42\x24"

    def test_be_addiu(self):
        arch = ArchMIPS64(Endness.BE)
        assert arch.asm("addiu $2, $2, 0xf") == b"\x24\x42\x00\x0f"


class TestPpc32Assembly(unittest.TestCase):
    def test_be_addi(self):
        arch = ArchPPC32(Endness.BE)
        assert arch.asm("addi 1, 1, 0xf") == b"\x38\x21\x00\x0f"

    def test_be_ori(self):
        arch = ArchPPC32(Endness.BE)
        assert arch.asm("ori 3, 3, 0xf") == b"\x60\x63\x00\x0f"


class TestPpc64Assembly(unittest.TestCase):
    def test_be_addi(self):
        arch = ArchPPC64(Endness.BE)
        assert arch.asm("addi 1, 1, 0xf") == b"\x38\x21\x00\x0f"

    def test_le_addi(self):
        arch = ArchPPC64(Endness.LE)
        assert arch.asm("addi 1, 1, 0xf") == b"\x0f\x00\x21\x38"


class TestRiscv64Assembly(unittest.TestCase):
    def test_addi(self):
        arch = ArchRISCV64(Endness.LE)
        assert arch.asm("addi a0, a0, 1") == b"\x13\x05\x15\x00"

    def test_add(self):
        arch = ArchRISCV64(Endness.LE)
        assert arch.asm("add a0, a1, a2") == b"\x33\x85\xc5\x00"


class TestS390xAssembly(unittest.TestCase):
    def test_ar(self):
        arch = ArchS390X(Endness.BE)
        assert arch.asm("ar %r1, %r2") == b"\x1a\x12"

    def test_lr(self):
        arch = ArchS390X(Endness.BE)
        assert arch.asm("lr %r1, %r2") == b"\x18\x12"


class TestErrorMessages(unittest.TestCase):
    def test_error_contains_instruction(self):
        arch = ArchAMD64(Endness.LE)
        try:
            arch.asm("mov rax, not_a_register")
            assert False, "Should have raised"
        except ArchError as e:
            assert "Assembly failed" in str(e)

    def test_error_on_empty_string(self):
        arch = ArchAMD64(Endness.LE)
        result = arch.asm("")
        assert result == b""


if __name__ == "__main__":
    unittest.main()
