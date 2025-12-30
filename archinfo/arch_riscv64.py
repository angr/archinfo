from archinfo.types import RegisterOffset

from .arch import Arch, Endness, Register, register_arch
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
    from unicorn import riscv_const
except ImportError:
    _unicorn = None
    riscv_const = None


def is_riscv_arch(a):
    return a.name.startswith("RISCV")


class ArchRISCV64(Arch):
    def __init__(self, endness=Endness.LE):
        super().__init__(endness)
        if endness == Endness.BE:
            self.function_prologs = set()
            self.function_epilogs = set()

    bits = 64
    vex_arch = "VexArchRISCV64"
    name = "RISCV64"
    qemu_name = "riscv64"
    linux_name = "riscv64"
    triplet = "riscv64-linux-gnu"
    max_inst_bytes = 4
    ret_offset = RegisterOffset(4)
    vex_conditional_helpers = True
    syscall_num_offset = 152
    call_pushes_ret = False
    stack_change = -8
    initial_sp = 0x7FFFFFFFFFF0000
    memory_endness = Endness.LE
    register_endness = Endness.LE
    instruction_endness = Endness.LE
    sizeof = {"short": 16, "int": 32, "long": 64, "long long": 64}
    if _capstone and hasattr(_capstone, "CS_ARCH_RISCV"):
        cs_arch = _capstone.CS_ARCH_RISCV
        cs_mode = _capstone.CS_MODE_RISCV64 | _capstone.CS_MODE_RISCVC
    # if _keystone:
    #     ks_arch = _keystone.KS_ARCH_RISCV
    #     ks_mode = _keystone.KS_MODE_LITTLE_ENDIAN
    uc_arch = _unicorn.UC_ARCH_RISCV if _unicorn else None
    uc_mode = _unicorn.UC_MODE_RISCV64 if _unicorn else None
    uc_const = riscv_const if _unicorn else None
    uc_prefix = "UC_RISCV_" if _unicorn else None

    ret_instruction = b"\x82\x80"  # ret
    nop_instruction = b"\x01\x00"  # nop
    function_prologs = set()
    function_epilogs = set()
    instruction_alignment = 2
    register_list = [
        Register(name="zero", size=8, alias_names=("x0",)),
        Register(
            name="ra",
            size=8,
            alias_names=(
                "x1",
                "lr",
            ),
            general_purpose=True,
        ),
        Register(name="sp", size=8, alias_names=("x2",), general_purpose=True),
        Register(name="gp", size=8, alias_names=("x3",), general_purpose=True),
        Register(name="tp", size=8, alias_names=("x4",), general_purpose=True),
        Register(name="t0", size=8, alias_names=("x5",), general_purpose=True),
        Register(name="t1", size=8, alias_names=("x6",), general_purpose=True),
        Register(name="t2", size=8, alias_names=("x7",), general_purpose=True),
        Register(name="s0", size=8, alias_names=("bp", "fp", "x8"), general_purpose=True, vex_offset=80),
        Register(name="s1", size=8, alias_names=("x9",), general_purpose=True),
        Register(name="a0", size=8, alias_names=("x10",), general_purpose=True, argument=True),
        Register(name="a1", size=8, alias_names=("x11",), general_purpose=True, argument=True),
        Register(name="a2", size=8, alias_names=("x12",), general_purpose=True, argument=True),
        Register(name="a3", size=8, alias_names=("x13",), general_purpose=True, argument=True),
        Register(name="a4", size=8, alias_names=("x14",), general_purpose=True, argument=True),
        Register(name="a5", size=8, alias_names=("x15",), general_purpose=True, argument=True),
        Register(name="a6", size=8, alias_names=("x16",), general_purpose=True, argument=True),
        Register(name="a7", size=8, alias_names=("x17",), general_purpose=True, argument=True),
        Register(name="s2", size=8, alias_names=("x18",), general_purpose=True),
        Register(name="s3", size=8, alias_names=("x19",), general_purpose=True),
        Register(name="s4", size=8, alias_names=("x20",), general_purpose=True),
        Register(name="s5", size=8, alias_names=("x21",), general_purpose=True),
        Register(name="s6", size=8, alias_names=("x22",), general_purpose=True),
        Register(name="s7", size=8, alias_names=("x23",), general_purpose=True),
        Register(name="s8", size=8, alias_names=("x24",), general_purpose=True),
        Register(name="s9", size=8, alias_names=("x25",), general_purpose=True),
        Register(name="s10", size=8, alias_names=("x26",), general_purpose=True),
        Register(name="s11", size=8, alias_names=("x27",), general_purpose=True),
        Register(name="t3", size=8, alias_names=("x28",), general_purpose=True),
        Register(name="t4", size=8, alias_names=("x29",), general_purpose=True),
        Register(name="t5", size=8, alias_names=("x30",), general_purpose=True),
        Register(name="t6", size=8, alias_names=("x31",), general_purpose=True),
        Register(name="pc", size=8, alias_names=("ip",)),
        Register(name="ft0", size=8, alias_names=("f0",), floating_point=True),
        Register(name="ft1", size=8, alias_names=("f1",), floating_point=True),
        Register(name="ft2", size=8, alias_names=("f2",), floating_point=True),
        Register(name="ft3", size=8, alias_names=("f3",), floating_point=True),
        Register(name="ft4", size=8, alias_names=("f4",), floating_point=True),
        Register(name="ft5", size=8, alias_names=("f5",), floating_point=True),
        Register(name="ft6", size=8, alias_names=("f6",), floating_point=True),
        Register(name="ft7", size=8, alias_names=("f7",), floating_point=True),
        Register(name="fs0", size=8, alias_names=("f8",), floating_point=True, vex_offset=344),
        Register(name="fs1", size=8, alias_names=("f9",), floating_point=True),
        Register(name="fa0", size=8, alias_names=("f10",), floating_point=True),
        Register(name="fa1", size=8, alias_names=("f11",), floating_point=True),
        Register(name="fa2", size=8, alias_names=("f12",), floating_point=True),
        Register(name="fa3", size=8, alias_names=("f13",), floating_point=True),
        Register(name="fa4", size=8, alias_names=("f14",), floating_point=True),
        Register(name="fa5", size=8, alias_names=("f15",), floating_point=True),
        Register(name="fa6", size=8, alias_names=("f16",), floating_point=True),
        Register(name="fa7", size=8, alias_names=("f17",), floating_point=True),
        Register(name="fs2", size=8, alias_names=("f18",), floating_point=True),
        Register(name="fs3", size=8, alias_names=("f19",), floating_point=True),
        Register(name="fs4", size=8, alias_names=("f20",), floating_point=True),
        Register(name="fs5", size=8, alias_names=("f21",), floating_point=True),
        Register(name="fs6", size=8, alias_names=("f22",), floating_point=True),
        Register(name="fs7", size=8, alias_names=("f23",), floating_point=True),
        Register(name="fs8", size=8, alias_names=("f24",), floating_point=True),
        Register(name="fs9", size=8, alias_names=("f25",), floating_point=True),
        Register(name="fs10", size=8, alias_names=("f26",), floating_point=True),
        Register(name="fs11", size=8, alias_names=("f27",), floating_point=True),
        Register(name="ft8", size=8, alias_names=("f28",), floating_point=True),
        Register(name="ft9", size=8, alias_names=("f29",), floating_point=True),
        Register(name="ft10", size=8, alias_names=("f30",), floating_point=True),
        Register(name="ft11", size=8, alias_names=("f31",), floating_point=True),
        Register(name="ip_at_syscall", size=8, artificial=True),
    ]

    got_section_name = ".got"
    ld_linux_name = "ld-linux-riscv64-lp64d.so.1"
    elf_tls = TLSArchInfo(1, 32, [], [0], [], 0, 0)


register_arch([r".*riscv.*"], 64, Endness.ANY, ArchRISCV64)
