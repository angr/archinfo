try:
    import capstone as _capstone
    if _capstone.__version__ < "5.0":
        raise ImportError("Only capstone verison >= 5.0 support RISC-V")
except ImportError:
    _capstone = None

from .arch import Arch, register_arch, Endness, Register
from .archerror import ArchError
from .tls import TLSArchInfo


class ArchRISCV(Arch):
    def __init__(self, endness=Endness.LE):
        if endness != Endness.LE:
            raise ArchError('Arch RISCV must be little endian')
        super(ArchRISCV, self).__init__(endness)

    address_types = (int,)
    function_address_types = (int,)

    name = "RISCV"
    bits = 32
    vex_arch = None # No VEX support
    qemu_name = None # No Unicorn-engine support
    ida_processor = None
    triplet = "riscv32-linux-gnu"
    max_inst_bytes = 4

    ip_offset = None
    sp_offset = None
    bp_offset = None
    lr_offset = None
    ret_offset = 11 # a0(x10) For return value

    vex_conditional_helpers = False
    syscall_num_offset = 8  # a7(x17) For syscall number (http://www.cs.uwm.edu/classes/cs315/Bacon/Lecture/HTML/ch05s03.html)
    call_pushes_ret = False
    stack_change = -4

    memory_endness = Endness.LE
    register_endness = Endness.LE
    instruction_endness = Endness.LE
    sizeof = {'short': 16, 'int': 32, 'long': 32, 'long long': 64}
    if _capstone:
        cs_arch = _capstone.CS_ARCH_RISCV
        cs_mode = _capstone.CS_MODE_RISCV32

    # TODO: Currently keystone, unicorn DON'T support RISC-V
    # if _keystone:
    #     ks_arch = _keystone.KS_ARCH_ALL
    #     ks_mode = _keystone.KS_MODE_ALL + _keystone.KS_MODE_LITTLE_ENDIAN
    # if _unicorn:
    #     uc_arch = _unicorn.UC_ARCH_ALL
    #     uc_mode = _unicorn.UC_MODE_LITTLE_ENDIAN
    #     uc_const = None
    #     uc_prefix = "UC_ALL_"
    # FIXME: overlap in sw and lw of prologs and epilogs
    function_prologs = {
        br"[\x00-\xff][\x00-\xf1]\x01\x13"
        # addi sp, sp, xxx
        # 0b000000000000_00010_000_00010_0010011 0x00010113 
        # 0b111111111111_00010_000_00010_0010011 0xfff10113
        br"[\x00-\xff][\x00-\xf1][\x20-\x2f][\x23-\xa3]"
        # sw xx, xx(sp)
        # 0b0000000_00000_00010_010_00000_0100011 0x00012023
        # 0b1111111_11111_00010_010_11111_0100011 0xfff12fa3
    }
    function_epilogs = {
        br"[\x00-\xff][\x00-\xf1][\x20-\x2f][\x23-\x83]"
        # ld xx, xx(sp)
        # 0b0000000_00000_00010_010_00000_0000011 0x00012003
        # 0b1111111_11111_00010_010_11111_0000011 0xfff12f83
        br"[\x00-\xff][\x00-\xf1]\x01\x13" # addi sp, sp, xxx
    }
    ret_instruction = b"\x00\x00\x80\x67"
    # jalr x0, x1, 0
    # 0b000000000000_00001_000_00000_1100111
    nop_instructoin = b"\x00\x00\x00\x13"
    # addi x0, x0, 0
    # 0b000000000000_00000_000_00000_0010011
    instruction_alignment = 4

    elf_tls = TLSArchInfo(1, 8, [], [0], [], 0, 0)

    register_list = [
       Register(name="x0", size = 4, alias_names=('zero',), vex_offset=0, default_value=(0,False, 0)),
       Register(name='x1', size = 4, alias_names=('ra','lr',), general_purpose=True, vex_offset = 4),
       Register(name='x2', size = 4, alias_names=('sp','bp'), general_purpose=True, default_value=(Arch.initial_sp, True, 'global'), vex_offset=8),
       Register(name='x3', size = 4, alias_names=('gp',), general_purpose=True, vex_offset=12),
       Register(name='x4', size = 4, alias_names=('tp',), general_purpose=True, vex_offset=16),
       Register(name='x5', size = 4, alias_names=('t0',), general_purpose=True, vex_offset=20),
       Register(name='x6', size = 4, alias_names=('t1',), general_purpose=True, vex_offset=24),
       Register(name='x7', size = 4, alias_names=('t2',), general_purpose=True, vex_offset=28),
       Register(name='x8', size = 4, alias_names=('s0','fp'), general_purpose=True, vex_offset=32),
       Register(name='x9', size = 4, alias_names=('s1',), general_purpose=True, vex_offset=36),
       Register(name='x10', size = 4, alias_names=('a0',), general_purpose=True, argument=True, vex_offset=40),
       Register(name='x11', size = 4, alias_names=('a1',), general_purpose=True, argument=True, vex_offset=44),
       Register(name='x12', size = 4, alias_names=('a2',), general_purpose=True, argument=True, vex_offset=48),
       Register(name='x13', size = 4, alias_names=('a3',), general_purpose=True, argument=True, vex_offset=52),
       Register(name='x14', size = 4, alias_names=('a4',), general_purpose=True, argument=True, vex_offset=56),
       Register(name='x15', size = 4, alias_names=('a5',), general_purpose=True, argument=True, vex_offset=60),
       Register(name='x16', size = 4, alias_names=('a6',), general_purpose=True, argument=True, vex_offset=64),
       Register(name='x17', size = 4, alias_names=('a7',), general_purpose=True, argument=True, vex_offset=68),
       Register(name='x18', size = 4, alias_names=('s2',), general_purpose=True, vex_offset=72),
       Register(name='x19', size = 4, alias_names=('s3',), general_purpose=True, vex_offset=76),
       Register(name='x20', size = 4, alias_names=('s4',), general_purpose=True, vex_offset=80),
       Register(name='x21', size = 4, alias_names=('s5',), general_purpose=True, vex_offset=84),
       Register(name='x22', size = 4, alias_names=('s6',), general_purpose=True, vex_offset=88),
       Register(name='x23', size = 4, alias_names=('s7',), general_purpose=True, vex_offset=92),
       Register(name='x24', size = 4, alias_names=('s8',), general_purpose=True, vex_offset=96),
       Register(name='x25', size = 4, alias_names=('s9',), general_purpose=True, vex_offset=100),
       Register(name='x26', size = 4, alias_names=('s10',), general_purpose=True, vex_offset=104),
       Register(name='x27', size = 4, alias_names=('s11',), general_purpose=True, vex_offset=108),
       Register(name='x28', size = 4, alias_names=('t3',), general_purpose=True, vex_offset=112),
       Register(name='x29', size = 4, alias_names=('t4',), general_purpose=True, vex_offset=116),
       Register(name='x30', size = 4, alias_names=('t5',), general_purpose=True, vex_offset=120),
       Register(name='x31', size = 4, alias_names=('t6',), general_purpose=True, vex_offset=124),
       Register(name='ip', alias_names={'pc',}, size=4, vex_offset=128),
    ]

    got_section_name = ".got"
    ld_linux_name = "ld-linux-riscv32-ilp32d.so.1"
    byte_width = 8


register_arch([r'.*riscv.*|.*rv32.*|.*risc-v.*'], 32, Endness.LE, ArchRISCV)
