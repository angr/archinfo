try:
    import capstone as _capstone
except ImportError:
    _capstone = None

try:
    import keystone as _keystone
except ImportError:
    _keystone = None

try:
    import pyvex as _pyvex
except ImportError:
    _pyvex = None

from .arch import Arch, register_arch, Endness, Register
from .archerror import ArchError
from .tls import TLSArchInfo


class ArchRISCV(Arch):
    def __init__(self, endness=Endness.LE):
        if endness != Endness.LE:
            raise ArchError('Arch RV32I must be little endian')
        super(ArchRISCV, self).__init__(endness)
        # FIXME: What this does?
        # if self.vex_archinfo:
        #    self.vex_archinfo['x86_cr0'] = 0xFFFFFFFF

    address_types = (int,)
    function_address_types = (int,)

    # various names
    name = "RISCV"  # type: str
    vex_arch = None
    qemu_name = None
    ida_processor = None
    linux_name = None
    triplet = None

    # instruction stuff
    max_inst_bytes = 4
    ret_instruction = b''
    nop_instruction = b''
    instruction_alignment = None

    # register ofsets
    ip_offset = None  # type: RegisterOffset
    sp_offset = None  # type: RegisterOffset
    bp_offset = None  # type: RegisterOffset
    ret_offset = None  # type: RegisterOffset
    lr_offset = None  # type: RegisterOffset

    # whether or not VEX has ccall handlers for conditionals for this arch
    vex_conditional_helpers = False

    # memory stuff
    bits = 32
    memory_endness = Endness.LE
    register_endness = Endness.LE
    stack_change = None

    # is it safe to cache IRSBs?
    cache_irsb = True

    branch_delay_slot = False

    function_prologs = set()
    function_epilogs = set()

    # Capstone stuff
    cs_arch = None
    cs_mode = None
    _cs = None

    # Keystone stuff
    ks_arch = None
    ks_mode = None
    _ks = None

    # Unicorn stuff
    uc_arch = None
    uc_mode = None
    uc_const = None
    uc_prefix = None
    uc_regs = None

    call_pushes_ret = False
    initial_sp = 0x7fff0000

    # Difference of the stack pointer after a call instruction (or its equivalent) is executed
    call_sp_fix = 0

    stack_size = 0x8000000

    # Register information
    register_list = [
        Register(name='x0', size=4, alias_names=("zero",)),
        Register(name='x1', size=4, alias_names=("ra",), general_purpose=True),
        Register(name='x2', size=4, alias_names=("sp",), general_purpose=True),
        Register(name='x3', size=4, alias_names=("gp",), general_purpose=True),
        Register(name='x4', size=4, alias_names=("tp",), general_purpose=True),
        Register(name='x5', size=4, alias_names=("t0",), general_purpose=True),
        Register(name='x6', size=4, alias_names=("t1",), general_purpose=True),
        Register(name='x7', size=4, alias_names=("t2",), general_purpose=True),
        Register(name='x8', size=4, alias_names=(
            "s0", "fp"), general_purpose=True),
        Register(name='x9', size=4, alias_names=("s1",), general_purpose=True),
        Register(name='x10', size=4, alias_names=("a0",),
                 general_purpose=True, argument=True),
        Register(name='x11', size=4, alias_names=("a1",),
                 general_purpose=True, argument=True),
        Register(name='x12', size=4, alias_names=("a2",),
                 general_purpose=True, argument=True),
        Register(name='x13', size=4, alias_names=("a3",),
                 general_purpose=True, argument=True),
        Register(name='x14', size=4, alias_names=("a4",),
                 general_purpose=True, argument=True),
        Register(name='x15', size=4, alias_names=("a5",),
                 general_purpose=True, argument=True),
        Register(name='x16', size=4, alias_names=("a6",),
                 general_purpose=True, argument=True),
        Register(name='x17', size=4, alias_names=("a7",),
                 general_purpose=True, argument=True),
        Register(name='x18', size=4, alias_names=(
            "s2",), general_purpose=True),
        Register(name='x19', size=4, alias_names=(
            "s3",), general_purpose=True),
        Register(name='x20', size=4, alias_names=(
            "s4",), general_purpose=True),
        Register(name='x21', size=4, alias_names=(
            "s5",), general_purpose=True),
        Register(name='x22', size=4, alias_names=(
            "s6",), general_purpose=True),
        Register(name='x23', size=4, alias_names=(
            "s7",), general_purpose=True),
        Register(name='x24', size=4, alias_names=(
            "s8",), general_purpose=True),
        Register(name='x25', size=4, alias_names=(
            "s9",), general_purpose=True),
        Register(name='x26', size=4, alias_names=(
            "s10",), general_purpose=True),
        Register(name='x27', size=4, alias_names=(
            "s11",), general_purpose=True),
        Register(name='x28', size=4, alias_names=(
            "t3",), general_purpose=True),
        Register(name='x29', size=4, alias_names=(
            "t4",), general_purpose=True),
        Register(name='x30', size=4, alias_names=(
            "t5",), general_purpose=True),
        Register(name='x31', size=4, alias_names=(
            "t6",), general_purpose=True),
    ]  # type: List[Register]

    default_register_values = []
    entry_register_values = {}
    default_symbolic_registers = []
    registers = {}  # type:  Dict[RegisterName, Tuple[RegisterOffset, int]]
    register_names = {}  # type: Dict[RegisterOffset, RegisterName]
    argument_registers = set()
    argument_register_positions = {}
    persistent_regs = []
    # this is a list of registers that should be concretized, if unique, at the end of each block
    concretize_unique_registers = set()

    lib_paths = []
    reloc_s_a = []
    reloc_b_a = []
    reloc_s = []
    reloc_copy = []
    reloc_tls_mod_id = []
    reloc_tls_doffset = []
    reloc_tls_offset = []
    dynamic_tag_translation = {}
    symbol_type_translation = {}
    got_section_name = ''

    vex_archinfo = None

    # FIXME: Copy From X86, May Incorrect!
    elf_tls = TLSArchInfo(2, 56, [8], [4], [0], 0, 0)


register_arch([r'.*riscv.*|.*rv32.*|.*risc-v.*'], 32, Endness.LE, ArchRISCV)
