from archinfo.types import RegisterOffset

from .arch import Arch, Endness, Register, register_arch
from .archerror import ArchError
from .tls import TLSArchInfo

try:
    import capstone as _capstone
except ImportError:
    _capstone = None

try:
    import keystone as _keystone
except ImportError:
    _keystone = None

try:
    import unicorn as _unicorn
except ImportError:
    _unicorn = None

try:
    import pyvex as _pyvex
except ImportError:
    _pyvex = None


_NATIVE_FUNCTION_PROLOGS = {
    rb"\x55\x48\x89\xe5",  # push rbp; mov rbp, rsp
    rb"\x48[\x83,\x81]\xec[\x00-\xff]",  # sub rsp, xxx
}
# every function prolog can potentially be prefixed with endbr64
_endbr64 = b"\xf3\x0f\x1e\xfa"
_prefixed = {(_endbr64 + prolog) for prolog in _NATIVE_FUNCTION_PROLOGS}
_FUNCTION_PROLOGS = _prefixed | _NATIVE_FUNCTION_PROLOGS


class ArchAMD64(Arch):
    def __init__(self, endness=Endness.LE):
        if endness != Endness.LE:
            raise ArchError("Arch AMD64 must be little endian")
        super().__init__(endness)
        self.argument_register_positions = (
            {
                self.registers["rdi"][0]: 0,
                self.registers["rsi"][0]: 1,
                self.registers["rdx"][0]: 2,
                self.registers["rcx"][0]: 3,  # Used for user calls
                self.registers["r10"][0]: 3,  # Used for Linux kernel calls
                self.registers["r8"][0]: 4,
                self.registers["r9"][0]: 5,
                # fp registers
                self.registers["xmm0"][0]: 0,
                self.registers["xmm1"][0]: 1,
                self.registers["xmm2"][0]: 2,
                self.registers["xmm3"][0]: 3,
                self.registers["xmm4"][0]: 4,
                self.registers["xmm5"][0]: 5,
                self.registers["xmm6"][0]: 6,
                self.registers["xmm7"][0]: 7,
            }
            if _pyvex is not None
            else None
        )

        # Register blacklist
        reg_blacklist = ("fs", "gs")
        if self.reg_blacklist is not None and self.reg_blacklist_offsets is not None:
            for register in self.register_list:
                if register.name in reg_blacklist:
                    self.reg_blacklist.append(register.name)
                    self.reg_blacklist_offsets.append(register.vex_offset)

        if _unicorn and _pyvex:
            # CPU flag registers
            uc_flags_reg = _unicorn.x86_const.UC_X86_REG_EFLAGS
            cpu_flag_registers = {"d": 1 << 10, "ac": 1 << 18, "id": 1 << 21}
            for reg, reg_bitmask in cpu_flag_registers.items():
                reg_offset = self.get_register_offset(reg)
                self.cpu_flag_register_offsets_and_bitmasks_map[reg_offset] = (uc_flags_reg, reg_bitmask)

            mxcsr_registers = {"sseround": 1 << 14 | 1 << 13}
            uc_mxcsr_reg = _unicorn.x86_const.UC_X86_REG_MXCSR
            for reg, reg_bitmask in mxcsr_registers.items():
                reg_offset = self.get_register_offset(reg)
                self.cpu_flag_register_offsets_and_bitmasks_map[reg_offset] = (uc_mxcsr_reg, reg_bitmask)

    @property
    def capstone_x86_syntax(self):
        """
        The current syntax Capstone uses for x64. It can be 'intel' or 'at&t'
        """
        return self._cs_x86_syntax

    @capstone_x86_syntax.setter
    def capstone_x86_syntax(self, new_syntax):
        if new_syntax not in ("intel", "at&t"):
            raise ArchError('Unsupported Capstone x86 syntax. It must be either "intel" or "at&t".')

        if new_syntax != self._cs_x86_syntax:
            self._cs = None
            self._cs_x86_syntax = new_syntax

    def _configure_capstone(self):
        if self._cs_x86_syntax == "at&t":
            self._cs.syntax = _capstone.CS_OPT_SYNTAX_ATT
        else:
            self._cs.syntax = _capstone.CS_OPT_SYNTAX_INTEL

    @property
    def keystone_x86_syntax(self):
        """
        The current syntax Keystone uses for x86. It can be 'intel',
        'at&t', 'nasm', 'masm', 'gas' or 'radix16'
        """
        return self._ks_x86_syntax

    @keystone_x86_syntax.setter
    def keystone_x86_syntax(self, new_syntax):
        if new_syntax not in ("intel", "at&t", "nasm", "masm", "gas", "radix16"):
            raise ArchError(
                "Unsupported Keystone x86 syntax. It must be one of the following: "
                '"intel", "at&t", "nasm", "masm", "gas" or "radix16".'
            )

        if new_syntax != self._ks_x86_syntax:
            self._ks = None
            self._ks_x86_syntax = new_syntax

    def _configure_keystone(self):
        if self._ks_x86_syntax == "at&t":
            self._ks.syntax = _keystone.KS_OPT_SYNTAX_ATT
        elif self._ks_x86_syntax == "nasm":
            self._ks.syntax = _keystone.KS_OPT_SYNTAX_NASM
        elif self._ks_x86_syntax == "masm":
            self._ks.syntax = _keystone.KS_OPT_SYNTAX_MASM
        elif self._ks_x86_syntax == "gas":
            self._ks.syntax = _keystone.KS_OPT_SYNTAX_GAS
        elif self._ks_x86_syntax == "radix16":
            self._ks.syntax = _keystone.KS_OPT_SYNTAX_RADIX16
        else:
            self._ks.syntax = _keystone.KS_OPT_SYNTAX_INTEL

    bits = 64
    vex_arch = "VexArchAMD64"
    vex_endness = "VexEndnessLE"
    name = "AMD64"
    pcode_id = "x86:LE:64:default"
    qemu_name = "x86_64"
    ida_processor = "metapc"
    linux_name = "x86_64"
    triplet = "x86_64-linux-gnu"
    max_inst_bytes = 15
    ret_offset = RegisterOffset(16)
    fp_ret_offset = RegisterOffset(224)  # xmm0
    vex_conditional_helpers = True
    syscall_num_offset = 16
    call_pushes_ret = True
    stack_change = -8
    initial_sp = 0x7FFFFFFF0000
    call_sp_fix = -8
    memory_endness = Endness.LE
    register_endness = Endness.LE
    sizeof = {"short": 16, "int": 32, "long": 64, "long long": 64}
    if _capstone:
        cs_arch = _capstone.CS_ARCH_X86
        cs_mode = _capstone.CS_MODE_64 + _capstone.CS_MODE_LITTLE_ENDIAN
    _cs_x86_syntax = None  # Set it to 'att' in order to use AT&T syntax for x86
    if _keystone:
        ks_arch = _keystone.KS_ARCH_X86
        ks_mode = _keystone.KS_MODE_64 + _keystone.KS_MODE_LITTLE_ENDIAN
    _ks_x86_syntax = None
    uc_arch = _unicorn.UC_ARCH_X86 if _unicorn else None
    uc_mode = (_unicorn.UC_MODE_64 + _unicorn.UC_MODE_LITTLE_ENDIAN) if _unicorn else None
    uc_const = _unicorn.x86_const if _unicorn else None
    uc_prefix = "UC_X86_" if _unicorn else None
    function_prologs = _FUNCTION_PROLOGS
    function_epilogs = {
        rb"\xc9\xc3",  # leaveq; retq
        rb"([^\x41][\x50-\x5f]{1}|\x41[\x50-\x5f])\xc3",  # pop <reg>; retq
        rb"\x48[\x83,\x81]\xc4([\x00-\xff]{1}|[\x00-\xff]{4})\xc3",  #  add rsp, <siz>; retq
    }
    ret_instruction = b"\xc3"
    nop_instruction = b"\x90"
    instruction_alignment = 1
    register_list = [
        Register(
            name="rax",
            size=8,
            subregisters=[("eax", 0, 4), ("ax", 0, 2), ("al", 0, 1), ("ah", 1, 1)],
            general_purpose=True,
            linux_entry_value=0x1C,
        ),
        Register(
            name="rcx",
            size=8,
            subregisters=[("ecx", 0, 4), ("cx", 0, 2), ("cl", 0, 1), ("ch", 1, 1)],
            general_purpose=True,
            argument=True,
        ),
        Register(
            name="rdx",
            size=8,
            subregisters=[("edx", 0, 4), ("dx", 0, 2), ("dl", 0, 1), ("dh", 1, 1)],
            general_purpose=True,
            argument=True,
            linux_entry_value="ld_destructor",
        ),
        Register(
            name="rbx",
            size=8,
            subregisters=[("ebx", 0, 4), ("bx", 0, 2), ("bl", 0, 1), ("bh", 1, 1)],
            general_purpose=True,
            linux_entry_value=0,
        ),
        Register(
            name="rsp",
            size=8,
            subregisters=[("esp", 0, 4)],
            alias_names=("sp",),
            general_purpose=True,
            default_value=(initial_sp, True, "global"),
        ),
        Register(
            name="rbp",
            size=8,
            subregisters=[("ebp", 0, 4), ("_bp", 0, 2), ("bpl", 0, 1), ("bph", 1, 1)],
            alias_names=("bp",),
            general_purpose=True,
            linux_entry_value=0,
        ),
        Register(
            name="rsi",
            size=8,
            subregisters=[("esi", 0, 4), ("si", 0, 2), ("sil", 0, 1), ("sih", 1, 1)],
            general_purpose=True,
            argument=True,
            linux_entry_value="argv",
        ),
        Register(
            name="rdi",
            size=8,
            subregisters=[("edi", 0, 4), ("di", 0, 2), ("dil", 0, 1), ("dih", 1, 1)],
            general_purpose=True,
            argument=True,
            linux_entry_value="argc",
        ),
        Register(
            name="r8",
            size=8,
            subregisters=[("r8d", 0, 4), ("r8w", 0, 2), ("r8b", 0, 1)],
            general_purpose=True,
            argument=True,
        ),
        Register(
            name="r9",
            size=8,
            subregisters=[("r9d", 0, 4), ("r9w", 0, 2), ("r9b", 0, 1)],
            general_purpose=True,
            argument=True,
        ),
        Register(
            name="r10",
            size=8,
            subregisters=[("r10d", 0, 4), ("r10w", 0, 2), ("r10b", 0, 1)],
            general_purpose=True,
            argument=True,
        ),
        Register(
            name="r11", size=8, subregisters=[("r11d", 0, 4), ("r11w", 0, 2), ("r11b", 0, 1)], general_purpose=True
        ),
        Register(
            name="r12",
            size=8,
            subregisters=[("r12d", 0, 4), ("r12w", 0, 2), ("r12b", 0, 1)],
            general_purpose=True,
            linux_entry_value=0,
        ),
        Register(
            name="r13",
            size=8,
            subregisters=[("r13d", 0, 4), ("r13w", 0, 2), ("r13b", 0, 1)],
            general_purpose=True,
            linux_entry_value=0,
        ),
        Register(
            name="r14",
            size=8,
            subregisters=[("r14d", 0, 4), ("r14w", 0, 2), ("r14b", 0, 1)],
            general_purpose=True,
            linux_entry_value=0,
        ),
        Register(
            name="r15",
            size=8,
            subregisters=[("r15d", 0, 4), ("r15w", 0, 2), ("r15b", 0, 1)],
            general_purpose=True,
            linux_entry_value=0,
        ),
        Register(name="cc_op", size=8, default_value=(0, False, None), concrete=False, artificial=True),
        Register(name="cc_dep1", size=8, concrete=False, artificial=True),
        Register(name="cc_dep2", size=8, concrete=False, artificial=True),
        Register(name="cc_ndep", size=8, concrete=False, artificial=True, linux_entry_value=0),
        Register(name="d", size=8, alias_names=("dflag",), default_value=(1, False, None), concrete=False),
        Register(name="rip", size=8, alias_names=("ip", "pc"), general_purpose=True),
        Register(name="ac", size=8, alias_names=("acflag",), concrete=False),
        Register(name="id", size=8, alias_names=("idflag",)),
        Register(
            name="fs",
            size=8,
            vex_name="fs_const",
            alias_names=("fs_const",),
            default_value=(0x9000000000000000, True, "global"),
            concrete=False,
        ),
        Register(name="sseround", size=8, vector=True, default_value=(0, False, None)),
        Register(name="cr0", size=8),
        Register(name="cr2", size=8),
        Register(name="cr3", size=8),
        Register(name="cr4", size=8),
        Register(name="cr8", size=8),
        Register(
            name="zmm0",
            size=64,
            subregisters=[
                ("ymm0", 0, 32),
                ("xmm0", 0, 16),
                ("xmm0lq", 0, 8),
                ("xmm0hq", 8, 8),
                ("ymm0hx", 16, 16),
                ("zmm0hy", 32, 32),
            ],
            vector=True,
        ),
        Register(
            name="zmm1",
            size=64,
            subregisters=[
                ("ymm1", 0, 32),
                ("xmm1", 0, 16),
                ("xmm1lq", 0, 8),
                ("xmm1hq", 8, 8),
                ("ymm1hx", 16, 16),
                ("zmm1hy", 32, 32),
            ],
            vector=True,
        ),
        Register(
            name="zmm2",
            size=64,
            subregisters=[
                ("ymm2", 0, 32),
                ("xmm2", 0, 16),
                ("xmm2lq", 0, 8),
                ("xmm2hq", 8, 8),
                ("ymm2hx", 16, 16),
                ("zmm2hy", 32, 32),
            ],
            vector=True,
        ),
        Register(
            name="zmm3",
            size=64,
            subregisters=[
                ("ymm3", 0, 32),
                ("xmm3", 0, 16),
                ("xmm3lq", 0, 8),
                ("xmm3hq", 8, 8),
                ("ymm3hx", 16, 16),
                ("zmm3hy", 32, 32),
            ],
            vector=True,
        ),
        Register(
            name="zmm4",
            size=64,
            subregisters=[
                ("ymm4", 0, 32),
                ("xmm4", 0, 16),
                ("xmm4lq", 0, 8),
                ("xmm4hq", 8, 8),
                ("ymm4hx", 16, 16),
                ("zmm4hy", 32, 32),
            ],
            vector=True,
        ),
        Register(
            name="zmm5",
            size=64,
            subregisters=[
                ("ymm5", 0, 32),
                ("xmm5", 0, 16),
                ("xmm5lq", 0, 8),
                ("xmm5hq", 8, 8),
                ("ymm5hx", 16, 16),
                ("zmm5hy", 32, 32),
            ],
            vector=True,
        ),
        Register(
            name="zmm6",
            size=64,
            subregisters=[
                ("ymm6", 0, 32),
                ("xmm6", 0, 16),
                ("xmm6lq", 0, 8),
                ("xmm6hq", 8, 8),
                ("ymm6hx", 16, 16),
                ("zmm6hy", 32, 32),
            ],
            vector=True,
        ),
        Register(
            name="zmm7",
            size=64,
            subregisters=[
                ("ymm7", 0, 32),
                ("xmm7", 0, 16),
                ("xmm7lq", 0, 8),
                ("xmm7hq", 8, 8),
                ("ymm7hx", 16, 16),
                ("zmm7hy", 32, 32),
            ],
            vector=True,
        ),
        Register(
            name="zmm8",
            size=64,
            subregisters=[
                ("ymm8", 0, 32),
                ("xmm8", 0, 16),
                ("xmm8lq", 0, 8),
                ("xmm8hq", 8, 8),
                ("ymm8hx", 16, 16),
                ("zmm8hy", 32, 32),
            ],
            vector=True,
        ),
        Register(
            name="zmm9",
            size=64,
            subregisters=[
                ("ymm9", 0, 32),
                ("xmm9", 0, 16),
                ("xmm9lq", 0, 8),
                ("xmm9hq", 8, 8),
                ("ymm9hx", 16, 16),
                ("zmm9hy", 32, 32),
            ],
            vector=True,
        ),
        Register(
            name="zmm10",
            size=64,
            subregisters=[
                ("ymm10", 0, 32),
                ("xmm10", 0, 16),
                ("xmm10lq", 0, 8),
                ("xmm10hq", 8, 8),
                ("ymm10hx", 16, 16),
                ("zmm10hy", 32, 32),
            ],
            vector=True,
        ),
        Register(
            name="zmm11",
            size=64,
            subregisters=[
                ("ymm11", 0, 32),
                ("xmm11", 0, 16),
                ("xmm11lq", 0, 8),
                ("xmm11hq", 8, 8),
                ("ymm11hx", 16, 16),
                ("zmm11hy", 32, 32),
            ],
            vector=True,
        ),
        Register(
            name="zmm12",
            size=64,
            subregisters=[
                ("ymm12", 0, 32),
                ("xmm12", 0, 16),
                ("xmm12lq", 0, 8),
                ("xmm12hq", 8, 8),
                ("ymm12hx", 16, 16),
                ("zmm12hy", 32, 32),
            ],
            vector=True,
        ),
        Register(
            name="zmm13",
            size=64,
            subregisters=[
                ("ymm13", 0, 32),
                ("xmm13", 0, 16),
                ("xmm13lq", 0, 8),
                ("xmm13hq", 8, 8),
                ("ymm13hx", 16, 16),
                ("zmm13hy", 32, 32),
            ],
            vector=True,
        ),
        Register(
            name="zmm14",
            size=64,
            subregisters=[
                ("ymm14", 0, 32),
                ("xmm14", 0, 16),
                ("xmm14lq", 0, 8),
                ("xmm14hq", 8, 8),
                ("ymm14hx", 16, 16),
                ("zmm14hy", 32, 32),
            ],
            vector=True,
        ),
        Register(
            name="zmm15",
            size=64,
            subregisters=[
                ("ymm15", 0, 32),
                ("xmm15", 0, 16),
                ("xmm15lq", 0, 8),
                ("xmm15hq", 8, 8),
                ("ymm15hx", 16, 16),
                ("zmm15hy", 32, 32),
            ],
            vector=True,
        ),
        Register(
            name="zmm16",
            size=64,
            subregisters=[
                ("ymm16", 0, 32),
                ("xmm16", 0, 16),
                ("xmm16lq", 0, 8),
                ("xmm16hq", 8, 8),
                ("ymm16hx", 16, 16),
                ("zmm16hy", 32, 32),
            ],
            vector=True,
        ),
        Register(
            name="zmm17",
            size=64,
            subregisters=[
                ("ymm17", 0, 32),
                ("xmm17", 0, 16),
                ("xmm17lq", 0, 8),
                ("xmm17hq", 8, 8),
                ("ymm17hx", 16, 16),
                ("zmm17hy", 32, 32),
            ],
            vector=True,
        ),
        Register(
            name="zmm18",
            size=64,
            subregisters=[
                ("ymm18", 0, 32),
                ("xmm18", 0, 16),
                ("xmm18lq", 0, 8),
                ("xmm18hq", 8, 8),
                ("ymm18hx", 16, 16),
                ("zmm18hy", 32, 32),
            ],
            vector=True,
        ),
        Register(
            name="zmm19",
            size=64,
            subregisters=[
                ("ymm19", 0, 32),
                ("xmm19", 0, 16),
                ("xmm19lq", 0, 8),
                ("xmm19hq", 8, 8),
                ("ymm19hx", 16, 16),
                ("zmm19hy", 32, 32),
            ],
            vector=True,
        ),
        Register(
            name="zmm20",
            size=64,
            subregisters=[
                ("ymm20", 0, 32),
                ("xmm20", 0, 16),
                ("xmm20lq", 0, 8),
                ("xmm20hq", 8, 8),
                ("ymm20hx", 16, 16),
                ("zmm20hy", 32, 32),
            ],
            vector=True,
        ),
        Register(
            name="zmm21",
            size=64,
            subregisters=[
                ("ymm21", 0, 32),
                ("xmm21", 0, 16),
                ("xmm21lq", 0, 8),
                ("xmm21hq", 8, 8),
                ("ymm21hx", 16, 16),
                ("zmm21hy", 32, 32),
            ],
            vector=True,
        ),
        Register(
            name="zmm22",
            size=64,
            subregisters=[
                ("ymm22", 0, 32),
                ("xmm22", 0, 16),
                ("xmm22lq", 0, 8),
                ("xmm22hq", 8, 8),
                ("ymm22hx", 16, 16),
                ("zmm22hy", 32, 32),
            ],
            vector=True,
        ),
        Register(
            name="zmm23",
            size=64,
            subregisters=[
                ("ymm23", 0, 32),
                ("xmm23", 0, 16),
                ("xmm23lq", 0, 8),
                ("xmm23hq", 8, 8),
                ("ymm23hx", 16, 16),
                ("zmm23hy", 32, 32),
            ],
            vector=True,
        ),
        Register(
            name="zmm24",
            size=64,
            subregisters=[
                ("ymm24", 0, 32),
                ("xmm24", 0, 16),
                ("xmm24lq", 0, 8),
                ("xmm24hq", 8, 8),
                ("ymm24hx", 16, 16),
                ("zmm24hy", 32, 32),
            ],
            vector=True,
        ),
        Register(
            name="zmm25",
            size=64,
            subregisters=[
                ("ymm25", 0, 32),
                ("xmm25", 0, 16),
                ("xmm25lq", 0, 8),
                ("xmm25hq", 8, 8),
                ("ymm25hx", 16, 16),
                ("zmm25hy", 32, 32),
            ],
            vector=True,
        ),
        Register(
            name="zmm26",
            size=64,
            subregisters=[
                ("ymm26", 0, 32),
                ("xmm26", 0, 16),
                ("xmm26lq", 0, 8),
                ("xmm26hq", 8, 8),
                ("ymm26hx", 16, 16),
                ("zmm26hy", 32, 32),
            ],
            vector=True,
        ),
        Register(
            name="zmm27",
            size=64,
            subregisters=[
                ("ymm27", 0, 32),
                ("xmm27", 0, 16),
                ("xmm27lq", 0, 8),
                ("xmm27hq", 8, 8),
                ("ymm27hx", 16, 16),
                ("zmm27hy", 32, 32),
            ],
            vector=True,
        ),
        Register(
            name="zmm28",
            size=64,
            subregisters=[
                ("ymm28", 0, 32),
                ("xmm28", 0, 16),
                ("xmm28lq", 0, 8),
                ("xmm28hq", 8, 8),
                ("ymm28hx", 16, 16),
                ("zmm28hy", 32, 32),
            ],
            vector=True,
        ),
        Register(
            name="zmm29",
            size=64,
            subregisters=[
                ("ymm29", 0, 32),
                ("xmm29", 0, 16),
                ("xmm29lq", 0, 8),
                ("xmm29hq", 8, 8),
                ("ymm29hx", 16, 16),
                ("zmm29hy", 32, 32),
            ],
            vector=True,
        ),
        Register(
            name="zmm30",
            size=64,
            subregisters=[
                ("ymm30", 0, 32),
                ("xmm30", 0, 16),
                ("xmm30lq", 0, 8),
                ("xmm30hq", 8, 8),
                ("ymm30hx", 16, 16),
                ("zmm30hy", 32, 32),
            ],
            vector=True,
        ),
        Register(
            name="zmm31",
            size=64,
            subregisters=[
                ("ymm31", 0, 32),
                ("xmm31", 0, 16),
                ("xmm31lq", 0, 8),
                ("xmm31hq", 8, 8),
                ("ymm31hx", 16, 16),
                ("zmm31hy", 32, 32),
            ],
            vector=True,
        ),
        Register(name="k0", size=8, vector=True),
        Register(name="k1", size=8, vector=True),
        Register(name="k2", size=8, vector=True),
        Register(name="k3", size=8, vector=True),
        Register(name="k4", size=8, vector=True),
        Register(name="k5", size=8, vector=True),
        Register(name="k6", size=8, vector=True),
        Register(name="k7", size=8, vector=True),
        Register(name="ftop", size=4, floating_point=True, default_value=(7, False, None), artificial=True),
        Register(
            name="fpreg",
            size=64,
            subregisters=[
                ("mm0", 0, 8),
                ("mm1", 8, 8),
                ("mm2", 16, 8),
                ("mm3", 24, 8),
                ("mm4", 32, 8),
                ("mm5", 40, 8),
                ("mm6", 48, 8),
                ("mm7", 56, 8),
            ],
            alias_names=("fpu_regs",),
            floating_point=True,
        ),
        Register(name="fptag", size=8, alias_names=("fpu_tags",), floating_point=True, default_value=(0, False, None)),
        Register(name="fpround", size=8, floating_point=True, default_value=(0, False, None)),
        Register(name="fc3210", size=8, floating_point=True),
        Register(name="emnote", size=4, artificial=True),
        Register(name="cmstart", size=8),
        Register(name="cmlen", size=8),
        Register(name="nraddr", size=8),
        Register(name="gs", size=8, vex_name="gs_const", alias_names=("gs_const",), concrete=False),
        Register(name="ip_at_syscall", size=8, concrete=False, artificial=True),
        Register(name="cs_seg", size=2, vex_name="cs"),
        Register(name="ds_seg", size=2, vex_name="ds"),
        Register(name="es_seg", size=2, vex_name="es"),
        Register(name="fs_seg", size=2, vex_name="fs"),
        Register(name="gs_seg", size=2, vex_name="gs"),
        Register(name="ss_seg", size=2, vex_name="ss"),
    ]

    # https://gitlab.com/x86-psABIs/x86-64-ABI
    dynamic_tag_translation = {
        0x70000000: "DT_X86_64_PLT",
        0x70000001: "DT_X86_64_PLTSZ",
        0x70000003: "DT_X86_64_PLTENT",
    }

    symbol_type_translation = {10: "STT_GNU_IFUNC", "STT_LOOS": "STT_GNU_IFUNC"}
    got_section_name = ".got.plt"
    ld_linux_name = "ld-linux-x86-64.so.2"
    elf_tls = TLSArchInfo(2, 704, [16], [8], [0], 0, 0)
    dwarf_registers = [
        "rax",
        "rdx",
        "rcx",
        "rbx",
        "rsi",
        "rdi",
        "rbp",
        "rsp",
        "r8",
        "r9",
        "r10",
        "r11",
        "r12",
        "r13",
        "r14",
        "r15",
        "rip",
        "xmm0",
        "xmm1",
        "xmm2",
        "xmm3",
        "xmm4",
        "xmm5",
        "xmm6",
        "xmm7",
        "xmm8",
        "xmm9",
        "xmm10",
        "xmm11",
        "xmm12",
        "xmm13",
        "xmm14",
        "xmm15",
        "st0",
        "st1",
        "st2",
        "st3",
        "st4",
        "st5",
        "st6",
        "st7",
        "mm0",
        "mm1",
        "mm2",
        "mm3",
        "mm4",
        "mm5",
        "mm6",
        "mm7",
        "rflags",
        "es",
        "cs",
        "ss",
        "ds",
        "fs",
        "gs",
        "<none>",
        "<none>",
        "fs.base",
        "gs.base",
        "<none>",
        "<none>",
        "tr",
        "ldtr",
        "mxcsr",
        "fcw",
        "fsw",
        # 67-82: xmm16-31 (AVX-512)
        "xmm16",
        "xmm17",
        "xmm18",
        "xmm19",
        "xmm20",
        "xmm21",
        "xmm22",
        "xmm23",
        "xmm24",
        "xmm25",
        "xmm26",
        "xmm27",
        "xmm28",
        "xmm29",
        "xmm30",
        "xmm31",
        # 83-117: reserved
        "<none>",
        "<none>",
        "<none>",
        "<none>",
        "<none>",
        "<none>",
        "<none>",
        "<none>",
        "<none>",
        "<none>",
        "<none>",
        "<none>",
        "<none>",
        "<none>",
        "<none>",
        "<none>",
        "<none>",
        "<none>",
        "<none>",
        "<none>",
        "<none>",
        "<none>",
        "<none>",
        "<none>",
        "<none>",
        "<none>",
        "<none>",
        "<none>",
        "<none>",
        "<none>",
        "<none>",
        "<none>",
        "<none>",
        "<none>",
        "<none>",
        # 118-125: k0-k7 (AVX-512 opmask registers)
        "k0",
        "k1",
        "k2",
        "k3",
        "k4",
        "k5",
        "k6",
        "k7",
    ]


register_arch([r".*amd64|.*x64|.*x86_64|.*metapc"], 64, Endness.LE, ArchAMD64)
