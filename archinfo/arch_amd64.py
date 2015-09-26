import capstone as _capstone

from .arch import Arch
from .archerror import ArchError

class ArchAMD64(Arch):
    def __init__(self, endness='Iend_LE'):
        if endness != 'Iend_LE':
            raise ArchError('Arch AMD64 must be little endian')
        super(ArchAMD64, self).__init__(endness)

    bits = 64
    vex_arch = "VexArchAMD64"
    vex_endness = "VexEndnessLE"
    name = "AMD64"
    qemu_name = 'x86_64'
    ida_processor = 'metapc'
    linux_name = 'x86_64'
    triplet = 'x86_64-linux-gnu'
    max_inst_bytes = 15
    ip_offset = 184
    sp_offset = 48
    bp_offset = 56
    ret_offset = 16
    syscall_num_offset = 16
    call_pushes_ret = True
    stack_change = -8
    initial_sp = 0x7ffffffffff0000
    call_sp_fix = -8
    memory_endness = "Iend_LE"
    register_endness = "Iend_LE"
    cs_arch = _capstone.CS_ARCH_X86
    cs_mode = _capstone.CS_MODE_64 + _capstone.CS_MODE_LITTLE_ENDIAN
    function_prologs = {
        r"\x55\x48\x89\xe5", # push rbp; mov rbp, rsp
        r"\x48[\x83,\x81]\xec[\x00-\xff]", # sub rsp, xxx
    }
    function_epilogs = {
        r"\xc9\xc3", # leaveq; retq
        r"([^\x41][\x50-\x5f]{1}|\x41[\x50-\x5f])\xc3", # pop <reg>; retq
        r"\x48[\x83,\x81]\xc4([\x00-\xff]{1}|[\x00-\xff]{4})\xc3", #  add rsp, <siz>; retq
    }
    ret_instruction = "\xc3"
    nop_instruction = "\x90"
    instruction_alignment = 1
    default_register_values = [
        ( 'd', 1, False, None ),
        ( 'rsp', initial_sp, True, 'global' ),
        ( 'fs', 0x9000000000000000, True, 'global'),
        ( 'sseround', 0, False, None ),
        ( 'fpround', 0, False, None ),
    ]
    entry_register_values = {
        'rax': 0x1c,
        'rdx': 'ld_destructor'
    }

    default_symbolic_registers = [ 'rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'rip' ]

    register_names = {
        16: 'rax',
        24: 'rcx',
        32: 'rdx',
        40: 'rbx',

        48: 'rsp',

        56: 'rbp',
        64: 'rsi',
        72: 'rdi',

        80: 'r8',
        88: 'r9',
        96: 'r10',
        104: 'r11',
        112: 'r12',
        120: 'r13',
        128: 'r14',
        136: 'r15',

        # condition stuff
        144: 'cc_op',
        152: 'cc_dep1',
        160: 'cc_dep2',
        168: 'cc_ndep',

        # this determines which direction SSE instructions go
        176: 'd',

        184: 'rip',

        208: 'fs',

        216: 'sseround',
        884: 'fpround'
    }

    registers = {
        'rax': (16, 8),
        'rcx': (24, 8),
        'rdx': (32, 8),
        'rbx': (40, 8),

        'sp': (48, 8),
        'rsp': (48, 8),

        'rbp': (56, 8), 'bp': (56, 8),
        'rsi': (64, 8),
        'rdi': (72, 8),

        'r8': (80, 8),
        'r9': (88, 8),
        'r10': (96, 8),
        'r11': (104, 8),
        'r12': (112, 8),
        'r13': (120, 8),
        'r14': (128, 8),
        'r15': (136, 8),

        # condition stuff
        'cc_op': (144, 8),
        'cc_dep1': (152, 8),
        'cc_dep2': (160, 8),
        'cc_ndep': (168, 8),

        # this determines which direction SSE instructions go
        'd': (176, 8),

        'rip': (184, 8),
        'pc': (184, 8),
        'ip': (184, 8),

        'fs': (208, 8),

        'sseround': (216, 8),
        'fpround': (848, 8)
    }

    argument_registers = {
        registers['rax'][0],
        registers['rcx'][0],
        registers['rdx'][0],
        registers['rbx'][0],
        registers['rsi'][0],
        registers['rdi'][0],
        registers['r8'][0],
        registers['r9'][0],
        registers['r10'][0],
        registers['r11'][0],
        registers['r12'][0],
        registers['r13'][0],
        registers['r14'][0],
        registers['r15'][0],
    }

    symbol_type_translation = {
        10: 'STT_GNU_IFUNC',
        'STT_LOOS': 'STT_GNU_IFUNC'
    }
    got_section_name = '.got.plt'
    ld_linux_name = 'ld-linux-x86-64.so.2'
