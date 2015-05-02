import capstone as _capstone

from .arch import Arch
from .archerror import ArchError

class ArchX86(Arch):
    def __init__(self, endness='Iend_LE'):
        if endness != 'Iend_LE':
            raise ArchError('Arch i386 must be little endian')
        super(ArchX86, self).__init__(endness)

    bits = 32
    vex_arch = "VexArchX86"
    name = "X86"
    qemu_name = 'i386'
    ida_processor = 'metapc'
    linux_name = 'i386'
    triplet = 'i386-linux-gnu'
    max_inst_bytes = 15
    call_sp_fix = -8
    ip_offset = 68
    sp_offset = 24
    bp_offset = 28
    ret_offset = 8
    call_pushes_ret = True
    stack_change = -4
    memory_endness = "Iend_LE"
    register_endness = "Iend_LE"
    cs_arch = _capstone.CS_ARCH_X86
    cs_mode = _capstone.CS_MODE_32 + _capstone.CS_MODE_LITTLE_ENDIAN
    function_prologs = {
        r"\x55\x8b\xec", # push ebp; mov ebp, esp
        r"\x55\x89\xe5",  # push ebp; mov ebp, esp
    }
    function_epilogs = {
        r"\xc9\xc3", # leave; ret
        r"([^\x41][\x50-\x5f]{1}|\x41[\x50-\x5f])\xc3", # pop <reg>; ret
        r"[^\x48][\x83,\x81]\xc4([\x00-\xff]{1}|[\x00-\xff]{4})\xc3", #  add esp, <siz>; retq
    }
    ret_instruction = "\xc3"
    nop_instruction = "\x90"
    instruction_alignment = 1
    default_register_values = [
        ( 'esp', Arch.initial_sp, True, 'global' ) # the stack
    ]
    entry_register_values = {
        'eax': 0x1C,
        'edx': 'ld_destructor',
        'ebp': 0
    }
    default_symbolic_registers = [ 'eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi', 'eip' ]
    register_names = {
        8: 'eax',
        12: 'ecx',
        16: 'edx',
        20: 'ebx',

        24: 'esp',

        28: 'ebp',
        32: 'esi',
        36: 'edi',

        # condition stuff
        40: 'cc_op',
        44: 'cc_dep1',
        48: 'cc_dep2',
        52: 'cc_ndep',

        # this determines which direction SSE instructions go
        56: 'd',

        68: 'eip',

        296: 'gs',
    }

    registers = {
        'eax': (8, 4),
        'ecx': (12, 4),
        'edx': (16, 4),
        'ebx': (20, 4),

        'sp': (24, 4),
        'esp': (24, 4),

        'ebp': (28, 4), 'bp': (28, 4),
        'esi': (32, 4),
        'edi': (36, 4),

        # condition stuff
        'cc_op': (40, 4),
        'cc_dep1': (44, 4),
        'cc_dep2': (48, 4),
        'cc_ndep': (52, 4),

        # this determines which direction SSE instructions go
        'd': (56, 4),

        'eip': (68, 4),
        'pc': (68, 4),
        'ip': (68, 4),

        'gs': (296, 2),
    }

    argument_registers = { registers['eax'][0],
                           registers['ecx'][0],
                           registers['edx'][0],
                           registers['ebx'][0],
                           registers['ebp'][0],
                           registers['esi'][0],
                           registers['edi'][0] }

    lib_paths = ['/lib32']
    reloc_s_a = [1]
    reloc_b_a = [8]
    reloc_s = [6]
    reloc_copy = [5]
    reloc_tls_mod_id = [15]
    reloc_tls_offset = [36,37] # wrong
    got_section_name = '.got.plt'
