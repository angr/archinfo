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


class ArchTILEGX(Arch):
    def __init__(self, endness=Endness.LE):
        super().__init__(endness)
        assert endness == Endness.LE

    bits = 64
    vex_arch = "VexArchTILEGX"
    name = "TILEGX"
    qemu_name = "tilegx"
    linux_name = "tilegx"
    triplet = "tilegx-linux-gnu"
    max_inst_bytes = 4
    ret_offset = RegisterOffset(4)
    vex_conditional_helpers = True
    syscall_num_offset = 132
    call_pushes_ret = False
    memory_endness = Endness.LE
    register_endness = Endness.LE
    instruction_endness = Endness.LE
    sizeof = {"short": 16, "int": 32, "long": 64, "long long": 64}
    if _capstone and hasattr(_capstone, "CS_ARCH_TILEGX"):
        cs_arch = _capstone.CS_ARCH_TILEGX
        cs_mode = _capstone.CS_MODE_TILEGX
    # if _keystone:
    #     ks_arch = _keystone.KS_ARCH_TILEGX
    #     ks_mode = _keystone.KS_MODE_LITTLE_ENDIAN
    uc_arch = _unicorn.UC_ARCH_TILEGX if _unicorn else None
    uc_mode = _unicorn.UC_MODE_TILEGX if _unicorn else None
    uc_const = riscv_const if _unicorn else None
    uc_prefix = "UC_TILEGX_" if _unicorn else None

    ret_instruction = b"\x00\x00\x80\x67"  # ret
    nop_instruction = b"\x00\x00\x00\x13"  # nop
    function_prologs = set()
    function_epilogs = set()
    instruction_alignment = 4
    register_list = [
        Register(name="r0", size=8, alias_names=("r0",), general_purpose=True),
        Register(name="r1", size=8, alias_names=("r1",), general_purpose=True),
        Register(name="r2", size=8, alias_names=("r2",), general_purpose=True),
        Register(name="r3", size=8, alias_names=("r3",), general_purpose=True),
        Register(name="r4", size=8, alias_names=("r4",), general_purpose=True),
        Register(name="r5", size=8, alias_names=("r5",), general_purpose=True),
        Register(name="r6", size=8, alias_names=("r6",), general_purpose=True),
        Register(name="r7", size=8, alias_names=("r7",), general_purpose=True),
        Register(name="r8", size=8, alias_names=("r8",), general_purpose=True),
        Register(name="r9", size=8, alias_names=("r9",), general_purpose=True),
        Register(name="r10", size=8, alias_names=("r10",), general_purpose=True),
        Register(name="r11", size=8, alias_names=("r11",), general_purpose=True),
        Register(name="r12", size=8, alias_names=("r12",), general_purpose=True),
        Register(name="r13", size=8, alias_names=("r13",), general_purpose=True),
        Register(name="r14", size=8, alias_names=("r14",), general_purpose=True),
        Register(name="r15", size=8, alias_names=("r15",), general_purpose=True),
        Register(name="r16", size=8, alias_names=("r16",), general_purpose=True),
        Register(name="r17", size=8, alias_names=("r17",), general_purpose=True),
        Register(name="r18", size=8, alias_names=("r18",), general_purpose=True),
        Register(name="r19", size=8, alias_names=("r19",), general_purpose=True),
        Register(name="r20", size=8, alias_names=("r20",), general_purpose=True),
        Register(name="r21", size=8, alias_names=("r21",), general_purpose=True),
        Register(name="r22", size=8, alias_names=("r22",), general_purpose=True),
        Register(name="r23", size=8, alias_names=("r23",), general_purpose=True),
        Register(name="r24", size=8, alias_names=("r24",), general_purpose=True),
        Register(name="r25", size=8, alias_names=("r25",), general_purpose=True),
        Register(name="r26", size=8, alias_names=("r26",), general_purpose=True),
        Register(name="r27", size=8, alias_names=("r27",), general_purpose=True),
        Register(name="r28", size=8, alias_names=("r28",), general_purpose=True),
        Register(name="r29", size=8, alias_names=("r29",), general_purpose=True),
        Register(name="r30", size=8, alias_names=("r30",), general_purpose=True),
        Register(name="r31", size=8, alias_names=("r31",), general_purpose=True),
        Register(name="r32", size=8, alias_names=("r32",), general_purpose=True),
        Register(name="r33", size=8, alias_names=("r33",), general_purpose=True),
        Register(name="r34", size=8, alias_names=("r34",), general_purpose=True),
        Register(name="r35", size=8, alias_names=("r35",), general_purpose=True),
        Register(name="r36", size=8, alias_names=("r36",), general_purpose=True),
        Register(name="r37", size=8, alias_names=("r37",), general_purpose=True),
        Register(name="r38", size=8, alias_names=("r38",), general_purpose=True),
        Register(name="r39", size=8, alias_names=("r39",), general_purpose=True),
        Register(name="r40", size=8, alias_names=("r40",), general_purpose=True),
        Register(name="r41", size=8, alias_names=("r41",), general_purpose=True),
        Register(name="r42", size=8, alias_names=("r42",), general_purpose=True),
        Register(name="r43", size=8, alias_names=("r43",), general_purpose=True),
        Register(name="r44", size=8, alias_names=("r44",), general_purpose=True),
        Register(name="r45", size=8, alias_names=("r45",), general_purpose=True),
        Register(name="r46", size=8, alias_names=("r46",), general_purpose=True),
        Register(name="r47", size=8, alias_names=("r47",), general_purpose=True),
        Register(name="r48", size=8, alias_names=("r48",), general_purpose=True),
        Register(name="r49", size=8, alias_names=("r49",), general_purpose=True),
        Register(name="r50", size=8, alias_names=("r50",), general_purpose=True),
        Register(name="r51", size=8, alias_names=("r51",), general_purpose=True),
        Register(name="r52", size=8, alias_names=("FP",), general_purpose=True),
        Register(name="r53", size=8, alias_names=("r53",), general_purpose=True),
        Register(name="r54", size=8, alias_names=("SP",), general_purpose=True),
        Register(name="r55", size=8, alias_names=("LR",), general_purpose=True),
        Register(name="r56", size=8, alias_names=("zero",), general_purpose=True),
        Register(name="r57", size=8, alias_names=("Reserved1",), general_purpose=True),
        Register(name="r58", size=8, alias_names=("Reserved2",), general_purpose=True),
        Register(name="r59", size=8, alias_names=("Reserved3",), general_purpose=True),
        Register(name="r60", size=8, alias_names=("Reserved4",), general_purpose=True),
        Register(name="r61", size=8, alias_names=("Reserved5",), general_purpose=True),
        Register(name="r62", size=8, alias_names=("Reserved6",), general_purpose=True),
        Register(name="r63", size=8, alias_names=("Reserved7",), general_purpose=True),
        Register(name="pc", size=8, alias_names=("pc",), general_purpose=True),
        # Register(name="x0", size=8, alias_names=("zero",)),
        # Register(
        #     name="x1",
        #     size=8,
        #     alias_names=(
        #         "ra",
        #         "lr",
        #     ),
        #     general_purpose=True,
        # ),
        # Register(name="x2", size=8, alias_names=("sp",), general_purpose=True),
        # Register(name="x3", size=8, alias_names=("gp",), general_purpose=True),
        # Register(name="x4", size=8, alias_names=("tp",), general_purpose=True),
        # Register(name="x5", size=8, alias_names=("t0",), general_purpose=True),
        # Register(name="x6", size=8, alias_names=("t1",), general_purpose=True),
        # Register(name="x7", size=8, alias_names=("t2",), general_purpose=True),
        # Register(name="x8", size=8, alias_names=("s0", "fp", "bp"), general_purpose=True),
        # Register(name="x9", size=8, alias_names=("s1",), general_purpose=True),
        # Register(name="x10", size=8, alias_names=("a0",), general_purpose=True, argument=True),
        # Register(name="x11", size=8, alias_names=("a1",), general_purpose=True, argument=True),
        # Register(name="x12", size=8, alias_names=("a2",), general_purpose=True, argument=True),
        # Register(name="x13", size=8, alias_names=("a3",), general_purpose=True, argument=True),
        # Register(name="x14", size=8, alias_names=("a4",), general_purpose=True, argument=True),
        # Register(name="x15", size=8, alias_names=("a5",), general_purpose=True, argument=True),
        # Register(name="x16", size=8, alias_names=("a6",), general_purpose=True, argument=True),
        # Register(name="x17", size=8, alias_names=("a7",), general_purpose=True, argument=True),
        # Register(name="x18", size=8, alias_names=("s2",), general_purpose=True),
        # Register(name="x19", size=8, alias_names=("s3",), general_purpose=True),
        # Register(name="x20", size=8, alias_names=("s4",), general_purpose=True),
        # Register(name="x21", size=8, alias_names=("s5",), general_purpose=True),
        # Register(name="x22", size=8, alias_names=("s6",), general_purpose=True),
        # Register(name="x23", size=8, alias_names=("s7",), general_purpose=True),
        # Register(name="x24", size=8, alias_names=("s8",), general_purpose=True),
        # Register(name="x25", size=8, alias_names=("s9",), general_purpose=True),
        # Register(name="x26", size=8, alias_names=("s10",), general_purpose=True),
        # Register(name="x27", size=8, alias_names=("s11",), general_purpose=True),
        # Register(name="x28", size=8, alias_names=("t3",), general_purpose=True),
        # Register(name="x29", size=8, alias_names=("t4",), general_purpose=True),
        # Register(name="x30", size=8, alias_names=("t5",), general_purpose=True),
        # Register(name="x31", size=8, alias_names=("t6",), general_purpose=True),
        # Register(name="pc", size=8, alias_names=("ip",)),
        # Register(
        #     name="f0",
        #     size=8,
        #     alias_names=("ft0",),
        #     floating_point=True,
        # ),
        # Register(name="f1", size=8, alias_names=("ft1",), floating_point=True),
        # Register(name="f2", size=8, alias_names=("ft2",), floating_point=True),
        # Register(name="f3", size=8, alias_names=("ft3",), floating_point=True),
        # Register(name="f4", size=8, alias_names=("ft4",), floating_point=True),
        # Register(name="f5", size=8, alias_names=("ft5",), floating_point=True),
        # Register(name="f6", size=8, alias_names=("ft6",), floating_point=True),
        # Register(name="f7", size=8, alias_names=("ft7",), floating_point=True),
        # Register(name="f8", size=8, alias_names=("fs0",), floating_point=True),
        # Register(name="f9", size=8, alias_names=("fs1",), floating_point=True),
        # Register(name="f10", size=8, alias_names=("fa0",), floating_point=True),
        # Register(name="f11", size=8, alias_names=("fa1",), floating_point=True),
        # Register(name="f12", size=8, alias_names=("fa2",), floating_point=True),
        # Register(name="f13", size=8, alias_names=("fa3",), floating_point=True),
        # Register(name="f14", size=8, alias_names=("fa4",), floating_point=True),
        # Register(name="f15", size=8, alias_names=("fa5",), floating_point=True),
        # Register(name="f16", size=8, alias_names=("fa6",), floating_point=True),
        # Register(name="f17", size=8, alias_names=("fa7",), floating_point=True),
        # Register(name="f18", size=8, alias_names=("fs2",), floating_point=True),
        # Register(name="f19", size=8, alias_names=("fs3",), floating_point=True),
        # Register(name="f20", size=8, alias_names=("fs4",), floating_point=True),
        # Register(name="f21", size=8, alias_names=("fs5",), floating_point=True),
        # Register(name="f22", size=8, alias_names=("fs6",), floating_point=True),
        # Register(name="f23", size=8, alias_names=("fs7",), floating_point=True),
        # Register(name="f24", size=8, alias_names=("fs8",), floating_point=True),
        # Register(name="f25", size=8, alias_names=("fs9",), floating_point=True),
        # Register(name="f26", size=8, alias_names=("fs10",), floating_point=True),
        # Register(name="f27", size=8, alias_names=("fs11",), floating_point=True),
        # Register(name="f28", size=8, alias_names=("ft8",), floating_point=True),
        # Register(name="f29", size=8, alias_names=("ft9",), floating_point=True),
        # Register(name="f30", size=8, alias_names=("ft10",), floating_point=True),
        # Register(name="f31", size=8, alias_names=("ft11",), floating_point=True),
        # Register(name="ip_at_syscall", size=8, artificial=True),
    ]

    got_section_name = ".got"
    ld_linux_name = "ld-linux-tilegx-lp64d.so.1"
    elf_tls = TLSArchInfo(1, 32, [], [0], [], 0, 0)


register_arch([r".*tilegx.*"], 64, Endness.LE, ArchTILEGX)
